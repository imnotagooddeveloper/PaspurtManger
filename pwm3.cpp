// g++ -std=c++11 -o pm password_manager.cpp -lpthread -lcrypto

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>
#include <iomanip>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#ifdef _WIN32
#include <conio.h>
#include <windows.h>
#else
#include <fcntl.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#endif

using namespace std;
using namespace std::chrono;

const string PLACEHOLDER_ACCOUNT  = "NoAccount";
const string PLACEHOLDER_MAIL     = "NoMail";
const string PLACEHOLDER_USERNAME = "NoUsername";
const string PLACEHOLDER_PASSWORD = "NoPassword";
const string PLACEHOLDER_NOTE     = "NoNote";

const string DEFAULT_FILE_NAME = "1.hbt";

constexpr int SALT_LEN  = 16;   // 128-bit salt
constexpr int NONCE_LEN = 16;   // 128-bit CTR
constexpr int KEY_LEN   = 32;   // 256-bit AES cool key
constexpr int PBKDF2_ITERATIONS = 600000;

static bool derive_key(const string& password, const vector<unsigned char>& salt,
                       unsigned char out_key[KEY_LEN]) {
    return PKCS5_PBKDF2_HMAC(
        password.c_str(), (int)password.size(),
        salt.data(), (int)salt.size(),
        PBKDF2_ITERATIONS,
        EVP_sha512(),
        KEY_LEN, out_key
    ) == 1;
}
static string encrypt_ctr(const string& plaintext, const string& password) {
    vector<unsigned char> salt(SALT_LEN), nonce(NONCE_LEN);
    if (RAND_bytes(salt.data(), SALT_LEN) != 1) return "";
    if (RAND_bytes(nonce.data(), NONCE_LEN) != 1) return "";

    unsigned char key[KEY_LEN];
    if (!derive_key(password, salt, key)) return "";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    vector<unsigned char> ct(plaintext.size() + 16);
    int len = 0, ct_len = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx); return "";
    }
    if (EVP_EncryptUpdate(ctx, ct.data(), &len,
                          reinterpret_cast<const unsigned char*>(plaintext.data()),
                          (int)plaintext.size()) != 1) {
        EVP_CIPHER_CTX_free(ctx); return "";
    }
    ct_len = len;
    if (EVP_EncryptFinal_ex(ctx, ct.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return "";
    }
    ct_len += len;
    EVP_CIPHER_CTX_free(ctx);

    string result;
    result.append(reinterpret_cast<char*>(salt.data()), SALT_LEN);
    result.append(reinterpret_cast<char*>(nonce.data()), NONCE_LEN);
    result.append(reinterpret_cast<char*>(ct.data()), ct_len);
    return result;
}

// Decryption never fails. Wrong password = asholic unreadable bytes.
static string decrypt_ctr(const string& blob, const string& password) {
    if (blob.size() < (size_t)(SALT_LEN + NONCE_LEN)) return "";

    const unsigned char* p = reinterpret_cast<const unsigned char*>(blob.data());
    vector<unsigned char> salt(p, p + SALT_LEN);
    vector<unsigned char> nonce(p + SALT_LEN, p + SALT_LEN + NONCE_LEN);
    const unsigned char* ct = p + SALT_LEN + NONCE_LEN;
    size_t ct_len = blob.size() - (SALT_LEN + NONCE_LEN);

    unsigned char key[KEY_LEN];
    if (!derive_key(password, salt, key)) return "";

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return "";

    vector<unsigned char> pt(ct_len + 16);
    int len = 0, pt_len = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, nonce.data()) != 1) {
        EVP_CIPHER_CTX_free(ctx); return "";
    }
    if (EVP_DecryptUpdate(ctx, pt.data(), &len, ct, (int)ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return "";
    }
    pt_len = len;
    if (EVP_DecryptFinal_ex(ctx, pt.data() + len, &len) != 1) {
        EVP_CIPHER_CTX_free(ctx); return "";
    }
    pt_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return string(reinterpret_cast<char*>(pt.data()), pt_len);
}

// Everything about keyboard / UTF-8 stuff
void copy_to_clipboard(const string& text) {
#ifdef _WIN32
    FILE* pipe = _popen("clip", "w");
    if (pipe) { fwrite(text.c_str(), 1, text.size(), pipe); fclose(pipe); }
#elif defined(__APPLE__)
    FILE* pipe = popen("pbcopy", "w");
    if (pipe) { fwrite(text.c_str(), 1, text.size(), pipe); pclose(pipe); }
#else
    FILE* pipe = popen("xclip -selection clipboard 2>/dev/null", "w");
    if (!pipe) pipe = popen("xsel -ib 2>/dev/null", "w");
    if (pipe) { fwrite(text.c_str(), 1, text.size(), pipe); pclose(pipe); }
#endif
}

enum Key {
    KEY_NONE = 0, KEY_UP, KEY_DOWN, KEY_LEFT, KEY_RIGHT,
    KEY_ENTER, KEY_ESC, KEY_BACKSPACE, KEY_UNKNOWN = 1000
};

size_t utf8_char_len(unsigned char c) {
    if (c < 0x80) return 1;
    if ((c & 0xE0) == 0xC0) return 2;
    if ((c & 0xF0) == 0xE0) return 3;
    if ((c & 0xF8) == 0xF0) return 4;
    return 1;
}
size_t utf8_count_chars(const string& s) {
    size_t count = 0;
    for (size_t i = 0; i < s.size();) { i += utf8_char_len((unsigned char)s[i]); ++count; }
    return count;
}
string utf8_remove_last_char(const string& s) {
    if (s.empty()) return s;
    size_t pos = s.size();
    while (pos > 0) { --pos; if (((unsigned char)s[pos] & 0xC0) != 0x80) break; }
    return s.substr(0, pos);
}

class KeyReader {
#ifdef _WIN32
    HANDLE hIn; DWORD mode;
public:
    KeyReader() {
        hIn = GetStdHandle(STD_INPUT_HANDLE);
        GetConsoleMode(hIn, &mode);
        SetConsoleMode(hIn, mode & ~(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT));
    }
    ~KeyReader() { SetConsoleMode(hIn, mode); }
    int getch() {
        int c = _getch();
        if (c == 0 || c == 0xE0) {
            int c2 = _getch();
            switch (c2) {
                case 72: return KEY_UP;
                case 80: return KEY_DOWN;
                case 75: return KEY_LEFT;
                case 77: return KEY_RIGHT;
                default: return KEY_UNKNOWN + c2;
            }
        }
        if (c == '\r') return KEY_ENTER;
        if (c == 27)  return KEY_ESC;
        if (c == 8)   return KEY_BACKSPACE;
        if (c >= 32 && c <= 126) return c;
        return KEY_UNKNOWN + c;
    }
#else
    termios oldt, newt;
public:
    KeyReader() {
        tcgetattr(STDIN_FILENO, &oldt);
        newt = oldt;
        newt.c_lflag &= ~(ICANON | ECHO);
        newt.c_cc[VMIN] = 1;
        newt.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    }
    ~KeyReader() { tcsetattr(STDIN_FILENO, TCSANOW, &oldt); }
    int getch() {
        char c;
        if (read(STDIN_FILENO, &c, 1) != 1) return KEY_NONE;
        if (c == '\x1b') {
            struct termios tmp = newt;
            tmp.c_cc[VMIN] = 0; tmp.c_cc[VTIME] = 1;
            tcsetattr(STDIN_FILENO, TCSANOW, &tmp);
            char seq[2];
            int n = read(STDIN_FILENO, seq, 2);
            tcsetattr(STDIN_FILENO, TCSANOW, &newt);
            if (n <= 0) return KEY_ESC;
            if (seq[0] == '[' && n >= 2) {
                switch (seq[1]) {
                    case 'A': return KEY_UP;
                    case 'B': return KEY_DOWN;
                    case 'C': return KEY_RIGHT;
                    case 'D': return KEY_LEFT;
                }
            }
            return KEY_UNKNOWN + (unsigned char)c;
        }
        if (c == '\n' || c == '\r') return KEY_ENTER;
        if (c == 127 || c == '\b') return KEY_BACKSPACE;
        return (unsigned char)c;
    }
#endif

    string read_line(const string& prompt, bool echo = true) {
        cout << prompt << flush;
        string buffer;
        while (true) {
            int ch = getch();
            if (ch == KEY_ENTER) { cout << endl; break; }
            else if (ch == KEY_BACKSPACE && !buffer.empty()) {
                string nb = utf8_remove_last_char(buffer);
                size_t removed = buffer.size() - nb.size();
                buffer = nb;
                for (size_t i = 0; i < removed; ++i) cout << "\b \b" << flush;
            } else if (ch >= 32 && ch <= 126) {
                buffer.push_back((char)ch);
                cout << (echo ? (char)ch : '*') << flush;
            } else if (ch >= 128 && ch <= 255) {
                string seq(1, (char)ch);
                size_t len = utf8_char_len((unsigned char)ch);
                for (size_t i = 1; i < len; ++i) {
                    int next = getch();
                    if (next >= 128 && next <= 191) seq.push_back((char)next);
                    else break;
                }
                if (seq.size() == len) {
                    buffer += seq;
                    cout << (echo ? seq : string(utf8_count_chars(seq), '*')) << flush;
                }
            }
        }
        return buffer;
    }
};

struct Entry { string account, mail, username, password, note; };

bool parse_csv_line(const string& line, Entry& out) {
    if (line.empty()) return false;
    istringstream iss(line);
    vector<string> fields;
    string field; bool in_quotes = false;
    auto read_next = [&]() -> int {
        field.clear(); in_quotes = false; char c;
        while (iss.get(c)) {
            if (!in_quotes) {
                if (c == '"') { in_quotes = true; continue; }
                if (c == ',') return 1;
                field += c;
            } else {
                if (c == '"') {
                    if (iss.peek() == '"') { field += '"'; iss.ignore(); }
                    else in_quotes = false;
                } else field += c;
            }
        }
        return 0;
    };
    while (true) {
        int r = read_next();
        fields.push_back(field);
        if (r == 0) break;
    }
    if (fields.size() == 4) {
        out.account  = fields[0]; out.mail = fields[1];
        out.username = fields[2]; out.password = fields[3];
        out.note = "";
        return true;
    }
    if (fields.size() == 5) {
        out.account  = fields[0]; out.mail = fields[1];
        out.username = fields[2]; out.password = fields[3];
        out.note = fields[4];
        return true;
    }
    return false;
}

string entry_to_csv(const Entry& e) {
    auto esc = [](const string& s) -> string {
        string r = "\"";
        for (char c : s) { if (c == '"') r += "\"\""; else r += c; }
        r += "\"";
        return r;
    };
    return esc(e.account) + "," + esc(e.mail) + "," + esc(e.username) + "," +
           esc(e.password) + "," + esc(e.note);
}

// TUI is best.
void move_cursor(int row, int col) { cout << "\033[" << row << ";" << col << "H" << flush; }
pair<int,int> term_size() {
#ifdef _WIN32
    CONSOLE_SCREEN_BUFFER_INFO csbi;
    GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &csbi);
    return pair<int,int>(csbi.srWindow.Bottom - csbi.srWindow.Top + 1,
                         csbi.srWindow.Right - csbi.srWindow.Left + 1);
#else
    winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0) return pair<int,int>(w.ws_row, w.ws_col);
    return pair<int,int>(24, 80);
#endif
}

vector<string> find_hbt_files() {
    vector<string> files;
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA("*.hbt", &fd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                files.push_back(fd.cFileName);
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);
    }
#else
    DIR* dir = opendir(".");
    if (dir) {
        struct dirent* ent;
        while ((ent = readdir(dir)) != nullptr) {
            string name = ent->d_name;
            if (name.size() > 4 && name.substr(name.size() - 4) == ".hbt") {
                struct stat st;
                if (stat(name.c_str(), &st) == 0 && S_ISREG(st.st_mode))
                    files.push_back(name);
            }
        }
        closedir(dir);
    }
#endif
    sort(files.begin(), files.end());
    return files;
}

string select_file() {
    vector<string> files = find_hbt_files();
    if (files.empty()) return DEFAULT_FILE_NAME;
    KeyReader kr;
    int selected = 0, cnt = (int)files.size() + 1;
    while (true) {
        clear_screen();
        pair<int,int> sz = term_size();
        int rows = sz.first, cols = sz.second;
        int start_row = max(1, (rows - cnt - 4) / 2);
        int start_col = max(1, (cols - 40) / 2);
        move_cursor(start_row, start_col);
        cout << "Select a .hbt password file:" << endl;
        for (int i = 0; i < cnt; ++i) {
            move_cursor(start_row + 2 + i, start_col);
            string label = (i < (int)files.size()) ? files[i] : "+ Create new file";
            cout << (i == selected ? "\033[7m" : "") << label
                 << (i == selected ? "\033[0m" : "") << endl;
        }
        move_cursor(start_row + cnt + 3, start_col);
        cout << "Up/Down: select   Enter: open   Esc: quit" << flush;
        int key = kr.getch();
        if (key == KEY_UP)        selected = (selected - 1 + cnt) % cnt;
        else if (key == KEY_DOWN) selected = (selected + 1) % cnt;
        else if (key == KEY_ENTER) {
            if (selected < (int)files.size()) return files[selected];
            clear_screen();
            string newname = kr.read_line("New file name (will append .hbt if missing): ", true);
            if (newname.empty()) continue;
            if (newname.size() < 4 || newname.substr(newname.size() - 4) != ".hbt")
                newname += ".hbt";
            return newname;
        }
        else if (key == KEY_ESC) exit(0);
    }
}

//  load() ALWAYS returns true; wrong password -> empty / garbage list (harder to find ur paspurt's 101%!)
class PasswordManager {
    vector<Entry> entries;
    string file_name;
    string master_password;
    mutable mutex mtx;

    void apply_placeholders(Entry& e) {
        if (e.account.empty())  e.account  = PLACEHOLDER_ACCOUNT;
        if (e.mail.empty())     e.mail     = PLACEHOLDER_MAIL;
        if (e.username.empty()) e.username = PLACEHOLDER_USERNAME;
        if (e.password.empty()) e.password = PLACEHOLDER_PASSWORD;
        if (e.note.empty())     e.note     = PLACEHOLDER_NOTE;
    }
    void sort_entries() {
        sort(entries.begin(), entries.end(),
             [](const Entry& a, const Entry& b) { return a.account < b.account; });
    }

public:
    PasswordManager(const string& fname, const string& password)
        : file_name(fname), master_password(password) {}

    bool load() {
        lock_guard<mutex> lock(mtx);
        ifstream in(file_name, ios::binary);
        if (!in) return true;   // new file
        string blob((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
        string plain = decrypt_ctr(blob, master_password);
        entries.clear();
        istringstream iss(plain);
        string line;
        while (getline(iss, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            Entry e;
            if (parse_csv_line(line, e)) entries.push_back(e);
        }
        sort_entries();
        return true;
    }

    bool save() {
        lock_guard<mutex> lock(mtx);
        string csv;
        for (const auto& e : entries) csv += entry_to_csv(e) + "\n";
        string blob = encrypt_ctr(csv, master_password);
        if (blob.empty()) return false;
        ofstream out(file_name, ios::binary);
        if (!out) return false;
        out.write(blob.data(), blob.size());
        return true;
    }

    void add(Entry e) {
        lock_guard<mutex> lock(mtx);
        apply_placeholders(e);
        entries.push_back(e);
        sort_entries();
    }
    void remove(int idx) {
        lock_guard<mutex> lock(mtx);
        if (idx >= 0 && idx < (int)entries.size()) entries.erase(entries.begin() + idx);
    }
    void update_field(int idx, int field, const string& value) {
        lock_guard<mutex> lock(mtx);
        if (idx < 0 || idx >= (int)entries.size()) return;
        Entry e = entries[idx];
        switch (field) {
            case 0: e.account = value.empty() ? PLACEHOLDER_ACCOUNT : value; break;
            case 1: e.mail    = value.empty() ? PLACEHOLDER_MAIL    : value; break;
            case 2: e.username= value.empty() ? PLACEHOLDER_USERNAME: value; break;
            case 3: e.password= value.empty() ? PLACEHOLDER_PASSWORD: value; break;
            case 4: e.note    = value.empty() ? PLACEHOLDER_NOTE    : value; break;
            default: return;
        }
        entries[idx] = e;
        sort_entries();
    }
    int import_file(const string& import_filename) {
        lock_guard<mutex> lock(mtx);
        ifstream fin(import_filename);
        if (!fin) { cerr << "Cannot open import file: " << import_filename << endl; return 0; }
        string line; int count = 0;
        while (getline(fin, line)) {
            if (!line.empty() && line.back() == '\r') line.pop_back();
            if (line.empty()) continue;
            Entry e;
            if (parse_csv_line(line, e)) { apply_placeholders(e); entries.push_back(e); ++count; }
            else cerr << "Skipping malformed line: " << line << endl;
        }
        sort_entries();
        return count;
    }
    int count() const { lock_guard<mutex> lock(mtx); return entries.size(); }
    Entry get(int i) const {
        lock_guard<mutex> lock(mtx);
        if (i >= 0 && i < (int)entries.size()) return entries[i];
        return Entry();
    }
    void export_plain_csv(const string& filename) {
        lock_guard<mutex> lock(mtx);
        ofstream out(filename);
        if (!out) { cerr << "Failed to open " << filename << endl; return; }
        for (const auto& e : entries) out << entry_to_csv(e) + "\n";
        cout << "Plain CSV exported to " << filename << " (" << entries.size() << " entries)" << endl;
    }
};

// Cool TUI
int show_main_menu() {
    KeyReader kr;
    vector<string> options;
    options.push_back(" View / Manage passwords ");
    options.push_back(" Add new password        ");
    options.push_back(" Import from CSV file    ");
    options.push_back(" Export plain CSV (unencrypted) ");
    options.push_back(" Save and exit           ");
    options.push_back(" Quit without saving     ");
    int selected = 0, cnt = options.size();
    while (true) {
        clear_screen();
        pair<int,int> sz = term_size();
        int rows = sz.first, cols = sz.second;
        int start_row = max(1, (rows - cnt - 2) / 2);
        int start_col = max(1, (cols - 30) / 2);
        move_cursor(start_row, start_col);
        cout << "Password Manager" << endl;
        for (int i = 0; i < cnt; ++i) {
            move_cursor(start_row + 2 + i, start_col);
            cout << (i == selected ? "\033[7m" : "") << options[i]
                 << (i == selected ? "\033[0m" : "") << endl;
        }
        move_cursor(start_row + cnt + 3, start_col);
        cout << "Use arrows + Enter, Esc to quit" << flush;
        int key = kr.getch();
        if (key == KEY_UP) selected = (selected - 1 + cnt) % cnt;
        else if (key == KEY_DOWN) selected = (selected + 1) % cnt;
        else if (key == KEY_ENTER) return selected;
        else if (key == KEY_ESC) return 5;
    }
}

bool is_placeholder(const string& s) {
    return s == PLACEHOLDER_ACCOUNT || s == PLACEHOLDER_MAIL ||
           s == PLACEHOLDER_USERNAME || s == PLACEHOLDER_PASSWORD ||
           s == PLACEHOLDER_NOTE;
}

void edit_single_field(PasswordManager& pm, int idx, int field) {
    Entry e = pm.get(idx);
    vector<string> field_names;
    field_names.push_back("Account");
    field_names.push_back("Mail");
    field_names.push_back("Username");
    field_names.push_back("Password");
    field_names.push_back("Note");
    clear_screen();
    cout << "Editing " << field_names[field] << " for entry #" << idx+1 << "\n\n";
    cout << "Current value: ";
    if (field == 3) cout << "[hidden]";
    else {
        string val = field==0 ? e.account : field==1 ? e.mail
                   : field==2 ? e.username : e.note;
        cout << val;
    }
    cout << "\n\nEnter new value (leave empty to keep unchanged): ";
    KeyReader kr;
    string new_val = kr.read_line("", field != 3);
    if (!new_val.empty()) { pm.update_field(idx, field, new_val); cout << "\nUpdated." << endl; }
    else                  cout << "\nUnchanged." << endl;
    this_thread::sleep_for(milliseconds(800));
}

void password_list_view(PasswordManager& pm) {
    KeyReader kr;
    int selected_row = 0, selected_col = 0;
    vector<string> col_names;
    col_names.push_back("Account");
    col_names.push_back("Mail");
    col_names.push_back("Username");
    col_names.push_back("Password");
    col_names.push_back("Note");
    const string ORANGE = "\033[33m";
    const string RESET  = "\033[0m";

    auto hpad = [](const string& s) { string r = s; r.resize(12, ' '); return r; };
    auto draw = [&]() {
        clear_screen();
        pair<int,int> sz = term_size();
        int rows = sz.first, cols = sz.second;
        int tsr = 2, tsc = 2;
        move_cursor(1, 2);
        cout << "Entries (" << pm.count() << ")   "
             << "\033[2mArrows:move, Enter:copy, a:add, d:del, e:edit, i:import, Esc:menu\033[0m" << endl;
        move_cursor(tsr, tsc);
        cout << "  # " << hpad("Account") << "  " << hpad("Mail") << "  "
             << hpad("Username") << "  " << hpad("Password") << "  " << hpad("Note") << endl;
        move_cursor(tsr+1, tsc);
        cout << string(72, '-') << endl;

        int total = pm.count();
        int vis = min(total, rows - tsr - 5);
        int first = max(0, selected_row - vis/2);
        if (first + vis > total) first = max(0, total - vis);
        for (int i = 0; i < vis; ++i) {
            int idx = first + i;
            Entry e = pm.get(idx);
            int row = tsr + 2 + i;
            move_cursor(row, tsc);
            if (idx == selected_row) cout << "\033[7m";
            cout << " " << setw(2) << (idx+1) << " ";
            auto print12 = [&](const string& s, int col) {
                string show = s.substr(0, 12); show.resize(12, ' ');
                bool ph = is_placeholder(s);
                if (ph) cout << ORANGE;
                if (idx == selected_row && col == selected_col) cout << "\033[1;33m";
                cout << show;
                if (idx == selected_row) cout << "\033[0m";
                if (ph) cout << RESET;
            };
            print12(e.account, 0);  cout << "  ";
            print12(e.mail, 1);     cout << "  ";
            print12(e.username, 2); cout << "  ";
            bool pwd_ph = is_placeholder(e.password);
            if (pwd_ph) cout << ORANGE;
            if (idx == selected_row && selected_col == 3) cout << "\033[1;33m****        \033[0m";
            else                                          cout << "****        ";
            if (pwd_ph) cout << RESET;
            cout << "  ";
            print12(e.note, 4);
            if (idx == selected_row) cout << "\033[0m";
        }
        move_cursor(tsr + 2 + vis + 1, tsc);
        cout << "Selected: " << col_names[selected_col] << " (Enter to copy)" << flush;
    };

    draw();
    while (true) {
        int key = kr.getch();
        bool redraw = true;
        int total = pm.count();
        switch (key) {
            case KEY_UP:    if (selected_row > 0) --selected_row; break;
            case KEY_DOWN:  if (selected_row < total-1) ++selected_row; break;
            case KEY_LEFT:  selected_col = (selected_col - 1 + 5) % 5; break;
            case KEY_RIGHT: selected_col = (selected_col + 1) % 5; break;
            case KEY_ENTER:
                if (total > 0 && selected_row < total) {
                    Entry e = pm.get(selected_row);
                    string val;
                    switch (selected_col) {
                        case 0: val = e.account; break;
                        case 1: val = e.mail; break;
                        case 2: val = e.username; break;
                        case 3: val = e.password; break;
                        case 4: val = e.note; break;
                    }
                    copy_to_clipboard(val);
                    pair<int,int> sz2 = term_size();
                    move_cursor(sz2.first, 1);
                    cout << "\033[K\033[1;32mCopied " << col_names[selected_col]
                         << " to clipboard.\033[0m" << flush;
                    this_thread::sleep_for(milliseconds(800));
                }
                break;
            case 'a': {
                clear_screen();
                cout << "Add new entry" << endl;
                Entry e;
                e.account = kr.read_line("Account: ", true);
                e.mail    = kr.read_line("Mail: ", true);
                e.username= kr.read_line("Username: ", true);
                e.password= kr.read_line("Password: ", false);
                e.note    = kr.read_line("Note: ", true);
                pm.add(e);
                if (selected_row >= pm.count()) selected_row = pm.count()-1;
                break;
            }
            case 'd':
                if (total > 0) {
                    clear_screen();
                    Entry e = pm.get(selected_row);
                    cout << "Delete entry #" << selected_row+1 << " (\"" << e.account.substr(0,10)
                         << "...\")? (y/n) " << flush;
                    int c = kr.getch();
                    if (c == 'y' || c == 'Y') {
                        pm.remove(selected_row);
                        if (selected_row >= pm.count() && selected_row > 0) --selected_row;
                    }
                }
                break;
            case 'e':
                if (total > 0) {
                    edit_single_field(pm, selected_row, selected_col);
                    if (selected_row >= pm.count()) selected_row = pm.count()-1;
                }
                break;
            case 'i': {
                clear_screen();
                string imp_file = kr.read_line("Enter filename to import (quoted CSV format): ", true);
                int cnt = pm.import_file(imp_file);
                clear_screen();
                cout << "Imported " << cnt << " entries." << endl;
                this_thread::sleep_for(milliseconds(1500));
                if (selected_row >= pm.count() && pm.count() > 0) selected_row = pm.count() - 1;
                break;
            }
            case KEY_ESC: return;
            default: redraw = false;
        }
        if (redraw) draw();
    }
}

// Finally, main
int main() {
    string file_name = select_file();
    KeyReader kr_temp;
    string master_key = kr_temp.read_line("Master password: ", false);
    if (master_key.empty()) { cerr << "Password cannot be empty." << endl; return 1; }

    PasswordManager pm(file_name, master_key);
    pm.load();

    while (true) {
        int choice = show_main_menu();
        switch (choice) {
            case 0: password_list_view(pm); break;
            case 1: {
                clear_screen();
                cout << "Add new password" << endl;
                KeyReader kr;
                Entry e;
                e.account = kr.read_line("Account: ", true);
                e.mail    = kr.read_line("Mail: ", true);
                e.username= kr.read_line("Username: ", true);
                e.password= kr.read_line("Password: ", false);
                e.note    = kr.read_line("Note: ", true);
                pm.add(e);
                cout << "Entry added." << endl;
                this_thread::sleep_for(milliseconds(800));
                break;
            }
            case 2: {
                clear_screen();
                KeyReader kr;
                string imp = kr.read_line("Enter filename to import: ", true);
                int cnt = pm.import_file(imp);
                clear_screen();
                cout << "Imported " << cnt << " entries." << endl;
                this_thread::sleep_for(milliseconds(1500));
                break;
            }
            case 3: {
                clear_screen();
                KeyReader kr;
                string export_file = kr.read_line("Enter filename for plain CSV export: ", true);
                pm.export_plain_csv(export_file);
                this_thread::sleep_for(milliseconds(1500));
                break;
            }
            case 4:
                if (pm.save()) cout << "Data saved to " << file_name << endl;
                else cerr << "Save failed!" << endl;
                return 0;
            case 5:
                cout << "Exiting without saving." << endl;
                return 0;
        }
    }
}
