/* 
   pwsafe - commandline tool compatible with Counterpane's Passwordsafe

   Copyright (C) 2004-2020 Nicolas S. Dade

   $Id$

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.  

*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_SIGNAL_H
#include <signal.h>
#endif
#if HAVE_GETOPT_H // freebsd for example doesn't have getopt.h but includes getopt() inside unistd.h
#include <getopt.h>
#endif
#if HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#if HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#if HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <errno.h>
#include <pwd.h>
#include <regex.h>
#if HAVE_SYS_MMAN_H
#include <sys/mman.h>
#endif
#include <limits.h>
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_SYS_RESOURCE_H
#include <sys/resource.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include <string>
#include <map>
#include <set>
#include <vector>
#include <algorithm>
#include <memory>
#include <fstream>

#include <termios.h>

#ifndef HAS_GETOPT_LONG
// our cheap substitute for getopt_long
// for testing we might have included a getopt.h that did include getopt_long, so
#ifdef no_argument
#undef no_argument
#undef required_argument
#undef optional_argument
#endif
struct long_option {
  const char* name;
  int has_arg;
  int* flag;
  int val;
};
static const int no_argument = 0;
static const int required_argument = 1;
// we don't support optional_argument in our cheap getopt_long
static int getopt_long(int, char*const[], const char*, const long_option*, int*);
#else
typedef struct option long_option;
#endif


#include <netinet/in.h> // for ntohl() to figure out the endianess

#include <openssl/sha.h>
#include <openssl/blowfish.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#ifndef X_DISPLAY_MISSING
#include <X11/Xlib.h>
#include <X11/Xatom.h>
#include <X11/Xmu/Atoms.h>
#include <X11/Xmu/WinUtil.h>
#endif

#ifndef HAVE_SOCKLEN_T
typedef int socklen_t;
#endif


// ---- secalloc and secstring classes ------------------------------------

// an (SGI style) allocator class that allocates from secure (non-swapable) storage
class secalloc {
public:
  static size_t pagesize;
  const static size_t alignsize;
private:
  struct Pool {
    Pool* next;
    char* top;
    char* bottom;
    char* level;
    Pool(size_t);
    ~Pool();
  };
  static Pool* pools;
public:
  explicit secalloc();
  static void init();
  static void cleanup();
  static void* allocate(size_t);
  static void deallocate(void*, size_t);
  static void* reallocate(void*, size_t, size_t);

  bool operator==(const secalloc&) const { return true; }
  bool operator!=(const secalloc&) const { return false; }

  // a struct that takes care of calling secalloc::cleanup() when it is destroyed (usefull to ensure that cleanup() is always called)
  struct Cleanup {
    Cleanup() { secalloc::init(); }
    ~Cleanup() { secalloc::cleanup(); }
  };
};
static secalloc::Cleanup cleanup_secalloc; // so secalloc::cleanup() is always called. Carefull, this must be the first global object so that global secstrings are destroyed first

// There are 4 different allocator interfaces I know of used by g++. g++ 2.9, 3.0, 3.x, x>=1, and 3.4.2.
// I used to try and use std::basic_string, but now I give up and implement my own stupid string
// class. Thank goodness for standards :-(

// a string class for handling strings that must not be swapped out---we use the secure allocator
class secstring {
public:
  typedef int size_type;
  static const size_type npos = -1;
private:
  char* txt;
  size_type len; // length of text
  size_type res; // length of buffer
  static char null_string;

  void construct(const char*, size_type, const char*, size_type);
  void deallocate() {
    if (txt != &null_string)
      secalloc::deallocate(txt,res+1);
  }
public:
  secstring() : txt(&null_string), len(0), res(0) {}
  secstring(const secstring&);
  secstring(const char*);
  secstring(const char*, size_type);
  secstring(const char*, const char*);
  secstring(const char*, size_type, const char*, size_type);
  ~secstring();

  bool operator == (const secstring&) const;
  bool operator != (const secstring& s) const { return ! operator==(s); }
  bool operator < (const secstring&) const;

  size_type find(char);
  size_type find_first_not_of(char);
  size_type find_last_not_of(char);

  const char& operator[] (size_t i) const { return txt[i]; }
  char& operator[] (size_t i) { return txt[i]; }
  const char* c_str() const { return txt; }
  const char* data() const { return txt; }
  size_t length() const { return len; }
  bool empty() const { return len == 0; }

  secstring& assign(const char*, size_type);
  secstring& assign(const char* t) { return assign(t,strlen(t)); }
  secstring& operator = (const char* t) { return assign(t); }
  secstring& operator = (const secstring& s) { return assign(s.c_str(),s.len); }
  secstring& append(const char*, size_type);
  secstring& operator += (char c) { return append(&c,1); }
  secstring& operator += (const char* t) { return append(t,strlen(t)); }
  secstring& operator += (const secstring& s) { return append(s.c_str(),s.len); }
  secstring substr(size_type, size_type);
  void erase() { operator=(&null_string); }
  void reserve(size_type);
  void resize(size_type);

  typedef const char* const_iterator;
  const_iterator begin() const { return txt; }
  const_iterator end() const { return txt+len; }
};

char secstring::null_string = '\0';

secstring::secstring(const secstring& s) : txt(&null_string), len(0), res(0) {
  assign(s.c_str(),s.length());
}

secstring::secstring(const char* t) : txt(&null_string), len(0), res(0) {
  assign(t);
}

secstring::secstring(const char* t, size_type l) : txt(&null_string), len(0), res(0) {
  assign(t,l);
}

secstring::secstring(const char* t1, const char* t2) : txt(&null_string), len(0), res(0) {
  construct(t1,strlen(t1),t2,strlen(t2));
}

secstring::secstring(const char* t1, size_type l1, const char* t2, size_type l2) : txt(&null_string), len(0), res(0) {
  construct(t1,l1,t2,l2);
}

void secstring::construct(const char* t1, size_type l1, const char* t2, size_type l2) {
  res = len = l1 + l2;
  txt = reinterpret_cast<char*>(secalloc::allocate(res+1));
  memcpy(txt,t1,l1);
  memcpy(txt+l1,t2,l2);
  txt[len] = '\0';
}

secstring::~secstring() { 
  deallocate();
}

secstring& secstring::assign(const char* t, size_type l) {
  if (t != txt) {
    deallocate();
    res = len = l;
    txt = reinterpret_cast<char*>(secalloc::allocate(res+1));
    memcpy(txt,t,len);
    txt[len] = '\0';
  }
  return *this;
}

secstring& secstring::append(const char* t, size_type l) {
  if (len+l > res)
    reserve(len+l);
  memcpy(txt+len,t,l);
  len += l;
  txt[len] = '\0';
  return *this;
}
secstring secstring::substr(size_type s, size_type e) {
  if (e == npos)
    e = len;
  return secstring(txt+s,e-s);
}

void secstring::reserve(size_type r) {
  if (res < r) {
    char* t = reinterpret_cast<char*>(secalloc::allocate(r+1));
    memcpy(t,txt,len+1);
    deallocate();
    txt = t;
    res = r;
  }
}
void secstring::resize(size_type r) {
  reserve(r);
  len = r;
  txt[r] = '\0';
}

bool secstring::operator==(const secstring& s) const {
  return this == &s ||
         (len == s.len &&
          memcmp(txt,s.txt,len) == 0);
}
bool secstring::operator<(const secstring& s) const {
  return strcmp(txt,s.txt) < 0;
}

secstring::size_type secstring::find(char c) {
  char* p = strchr(txt,c);
  return p ? p-txt : npos;
}
secstring::size_type secstring::find_first_not_of(char c) {
  for (size_type p = 0; p < len; p++)
    if (txt[p] != c)
      return p;
  return npos;
}
secstring::size_type secstring::find_last_not_of(char c) {
  for (size_type p = len-1; p >= 0; p--)
    if (txt[p] != c)
      return p;
  return npos;
}

secstring operator+(const secstring& t1, const secstring& t2) { 
  return secstring(t1.c_str(),t1.length(),t2.c_str(),t2.length()); 
}
secstring operator+(const char* t1, const secstring& t2) { 
  return secstring(t1,strlen(t1),t2.c_str(),t2.length()); 
}
secstring operator+(const secstring& t1, const char* t2) { 
  return secstring(t1.c_str(),t1.length(),t2,strlen(t2)); 
}
secstring operator+(const secstring& t1, char c) { 
  return secstring(t1.c_str(),t1.length(),&c,1);
}
  

  
// ------ end of fixups for various systems; on to the real program ------

// The name the program was run with, stripped of any leading path
const char *program_name = "pwsafe"; // make sure program_name always points to something valid so we can use it in constructors of globals
uid_t saved_uid;
gid_t saved_gid;

// database version
enum Version { VERSION_UNKNOWN, VERSION_1_7, VERSION_2_0 };
const static char*const VERSION_NAME[] = { "<unknown>", "1.7", "2.0" };

// Option flags and variables
const char* arg_dbname = NULL;
Version arg_dbversion = VERSION_UNKNOWN;
const char* arg_mergedb = NULL;
const char* arg_name = NULL;
enum OP { 
  OP_NOP, OP_CREATEDB, OP_EXPORTDB, OP_MERGEDB, OP_PASSWD, OP_LIST, OP_EMIT, OP_ADD, OP_EDIT, OP_DELETE, 
};
OP arg_op = OP_NOP;
//const char* arg_config = NULL;
const char* arg_askpass = NULL;
bool arg_casesensative = false;
bool arg_echo = false;
const char* arg_output = NULL;
FILE* outfile = NULL; // will be arg_output() or stdout
bool arg_username = false;
bool arg_password = false;
bool arg_twice = false;
bool arg_details = false;
int arg_verbose = 0;
int arg_debug = 0;
#ifndef X_DISPLAY_MISSING
bool arg_xclip = false;
const char* arg_display = NULL;
const char* arg_selection = "both"; // by default copy to primary X selection and clipboard
typedef std::set<std::string> arg_ignore_t;
arg_ignore_t arg_ignore;
static Display* xdisplay = NULL;
const char* xsel_names = NULL;
#endif

static long_option const long_options[] =
{
  // commands
  {"createdb", no_argument, 0, 'C'},
  {"exportdb", no_argument, 0, 'E'&31},
  {"mergedb", required_argument, 0, 'M'&31},
  {"passwd", no_argument, 0, 'P'},
  {"list", no_argument, 0, 'L'},
  {"add", no_argument, 0, 'a'},
  {"edit", no_argument, 0, 'e'},
  {"delete", no_argument, 0, 'D'},
  // options
//  {"config", required_argument, 0, 'F'},
  {"askpass", required_argument, 0, 'A'},
  {"file", required_argument, 0, 'f'},
  {"case", no_argument, 0 ,'I'},
  // options controlling what is outputted
  {"long", no_argument, 0, 'l'},
  {"username", no_argument, 0, 'u'},
  {"password", no_argument, 0, 'p'},
  {"twice", no_argument, 0, 't'},
  // options controlling where output goes
  {"echo", no_argument, 0, 'E'},
  {"output", required_argument, 0, 'o'},
  {"dbversion", required_argument, 0, 'V'&31},
#ifndef X_DISPLAY_MISSING
  {"xclip", no_argument, 0, 'x'},
  {"display", required_argument, 0,'d'},
  {"selection", required_argument, 0,'s'},
  {"ignore", required_argument, 0,'G'},
#endif
  // standard stuff
  {"quiet", no_argument, 0, 'q'},
  {"verbose", no_argument, 0, 'v'},
  {"help", no_argument, 0, 'h'},
  {"version", no_argument, 0, 'V'},
  {NULL, 0, NULL, 0}
};


static void usage(bool fail);
static int parse(int argc, char **argv);
static const char* pwsafe_strerror(int err); // decodes errno's as well as our negative error codes
#define PWSAFE_ERR_INVALID_DB -1

static char get1char(const char* prompt, int def_val=-1);
static bool getyn(const char* prompt, int def_val=-1);

// (unused at the moment) static inline char get1char(const std::string& prompt, int def_val=-1) { return get1char(prompt.c_str(), def_val); }
static inline char get1char(const secstring& prompt, int def_val=-1) { return get1char(prompt.c_str(), def_val); }
static inline bool getyn(const std::string& prompt, int def_val=-1) { return getyn(prompt.c_str(), def_val); }
static inline bool getyn(const secstring& prompt, int def_val=-1) { return getyn(prompt.c_str(), def_val); }

struct FailEx {}; // thrown to unwind, cleanup and cause main to return 1
struct ExitEx { const int rc; explicit ExitEx(int c) : rc(c) {} }; // thrown to unwind and exit() with rc

// a blowfish data block (8 bytes)
class Block {
private:
  BF_LONG block[2];
  static void makeLE(unsigned char[8]);
public:
  operator BF_LONG*() { return block; }
  Block() {}
  ~Block();
  void zero();

  void putInt32AndType(int32_t, uint8_t);
  int32_t getInt32() const;
  uint8_t getType() const;

  Block& operator ^=(const Block&);

  void read(const unsigned char*, int len);
  void write(unsigned char[8]) const;

  bool read(FILE*);
  bool write(FILE*) const;
};
  

class DB {
private:
  // the file header, which is kept in secalloc just like the secstrings
  struct Header {
    unsigned char random[8];
    unsigned char hash[SHA_DIGEST_LENGTH]; // 20
    unsigned char salt[SHA_DIGEST_LENGTH]; // 20
    unsigned char iv[8];

    Header();
    ~Header();
    void zero();
    bool create();
    bool resalt();
    bool read(FILE*);
    bool write(FILE*) const;

    // overload new and delete to the Header is kept in secalloc's memory
    void* operator new(size_t n) { return secalloc::allocate(n); }
    void operator delete(void* p,size_t n) { secalloc::deallocate(p,n); }
  };
  Header* header;

  // the crypto context (exists only when read/writing the database). also kept in secalloc memory
  struct Context {
    Block cbc;
    BF_KEY bf;
    const Version& version; // typically points back to DB's Version

    Context(const Header&, const secstring& pw, const Version&);
    ~Context();

    // overload new and delete so Context is kept in secalloc's memory
    void* operator new(size_t n) { return secalloc::allocate(n); }
    void operator delete(void* p,size_t n) { secalloc::deallocate(p,n); }
  };

  struct Entry {
  public:
    typedef std::vector< std::pair<unsigned int,secstring> > extras_t;
  private:
    // the name+login fields are saved as one string in the file for historical reasons (login was added after 1.0), seperated by magic characters we hope you won't use in a name
    const static char SPLIT_CHAR = '\xAD';
    const static char*const SPLIT_STR; // = "  \xAD  "
    const static char DEFAULT_USER_CHAR = '\xA0';
  
    // version 2 field types
    enum Type { NAME=0, UUID=0x1, GROUP = 0x2, TITLE = 0x3, USER = 0x4, NOTES = 0x5, PASSWORD = 0x6, 
         // future fields: CTIME = 0x7, MTIME = 0x8, ATIME = 0x9, LTIME = 0xa, POLICY = 0xb, 
                END = 0xff};

    static bool read(FILE*, Context&, uint8_t& type, secstring&);
    static bool write(FILE*, Context&, uint8_t type, const secstring&);
    static bool write(FILE*, Context&, const extras_t&);

  public:
    const static char*const MAGIC_V2_NAME; // = " !!!Version 2 File Format!!! ..."
    const static char*const MAGIC_V2_PASSWORD; // = "2.0"

    static secstring the_default_login;
    secstring name;
    secstring login;
    bool default_login;
    secstring password;
    secstring notes;
    // new v2.0 values
    secstring uuid; // I exploit the fact that std::string can contain '\0'
    secstring group;
    // unknown v2.0+ values are stored as binary, so when the file is saved we can restore them (hopefully this doesn't lead to inconsistencies)
    extras_t extras;

    static void Init(); // computes the_default_login
    Entry();
    bool read(FILE*, Context&);
    bool write(FILE*, Context&) const;

    bool operator!=(const Entry&) const;
    bool operator==(const Entry& e) const { return !operator!=(e); }
    int diff(const Entry&, secstring& summary) const;
    secstring diff(const Entry&) const;

    secstring groupname() const;
  };
  typedef std::map<secstring, Entry> entries_t;
  entries_t entries;
  typedef std::vector<const Entry*> matches_t;

  secstring passphrase;
  Version version;
  secstring v2_preferences;
  bool opened; // true after open() has succeeded
  bool changed; // unsaved changes have been made
  bool backedup; // true after backup() has succeeded
  bool overwritten; // true once we start overwriting dbname
  
  bool getkey(bool test, const char* prompt1="Enter passphrase", const char* prompt2="Reenter passphrase"); // get/verify passphrase
  bool testkey(const secstring&);
  void hashkey(const secstring&, unsigned char test_hash[]);

  bool add(const Entry&); // add entry into database
  bool del(const Entry&); // remove entry from database
  bool find(matches_t&, const char* regex); // find all entries matching regex
  const Entry& find1(const char* regex); // find the one entry either == regex or matching; throw FailEx if 0 or >1 match
public:
  const std::string dbname_str;
  const char*const dbname;

  static void Init();
  DB(const char* dbname, Version=VERSION_UNKNOWN);
  ~DB();

  static void createdb(const char* dbname);
  bool open(const secstring* pw_to_try=NULL); // call getkey(), read file into entries map
  void exportdb();
  void mergedb(DB&);
  void passwd();
  void list(const char* regex);
  void emit(const char* regex, bool username, bool password, bool twice);
  void add(const char* name);
  void edit(const char* regex);
  void del(const char* name);

  bool is_changed() const { return changed; }

  bool backup(); // create ~ file
  bool save(); // write out db file (please backup() first if appropriate)
  bool restore(); // copy ~ file back to original (only if an earlier call to backup() suceeded)
  
  static const secstring& defaultlogin() { return Entry::the_default_login; }
};


int main(int argc, char **argv) {
  program_name = strrchr(argv[0], '/');
  if (!program_name)
    program_name = argv[0];
  else
    program_name++;

  try {
    try {
      saved_uid = geteuid();
      saved_gid = getegid();
      
      // if we are running suid, drop privileges now; we use seteuid() instead of setuid() so the saved uid remains root and we can become root again in order to mlock()
      if (saved_uid != getuid() || saved_gid != getgid()) {
        int dont_care = setegid(getgid());
        dont_care = seteuid(getuid());
        (void)dont_care; // shut gcc up about these
      }

      // be nice and paranoid
      umask(0077);

      // init some arguments
      {
        // use $PWSAFE_DATABASE (which might be a full path or just a filename relative to home), and fall back on ".pwsafe.dat"
        const char* datname = getenv("PWSAFE_DATABASE");
        if (!datname)
          datname = ".pwsafe.dat";
        
        const char* home = getenv("HOME");
        if (home && datname[0] != '/') {
          char* dbname = reinterpret_cast<char*>(malloc(strlen(home)+1+strlen(datname)+1));
          strcpy(dbname, home);
          strcat(dbname, "/");
          strcat(dbname, datname);
          arg_dbname = dbname;
        } else {
          // datname is already an absolute path
          arg_dbname = datname;
        }

#ifndef X_DISPLAY_MISSING
        if (isatty(STDOUT_FILENO) && (arg_display = XDisplayName(NULL)) && strlen(arg_display))
          arg_xclip = true;
        else
#endif
          arg_echo = true;
      }

      int idx = parse(argc, argv);
   
#ifndef X_DISPLAY_MISSING
      // if no --ignore was specified, use the default
      if (arg_ignore.empty()) {
        const char* ig = getenv("PWSAFE_IGNORE");
        if (!ig) ig = "xclipboard:klipper:wmcliphist:<unknown>";
        while (*ig) {
          const char*const q = ig;
          while (*ig && *ig != ':') ++ig;
          arg_ignore.insert(arg_ignore_t::value_type(q,ig-q));
          while (*ig == ':') ++ig;
        }
      }
#endif
      if (arg_op == OP_NOP)
        // assume --list
        arg_op = OP_LIST;

      if (arg_op == OP_LIST && (arg_username || arg_password))
        // this is actually an OP_EMIT and not an OP_LIST
        arg_op = OP_EMIT;
      
      if (idx != argc) {
        if ((arg_op == OP_LIST || arg_op == OP_EMIT || arg_op == OP_ADD || arg_op == OP_EDIT || arg_op == OP_DELETE) && idx+1 == argc) {
          arg_name = argv[idx];
        } else {
          fprintf(stderr, "%s - Too many arguments\n", program_name);
          usage(true);
        }
      }

      if (!arg_dbname) {
          // $PWSAFE_DATABASE and $HOME weren't set and -f wasn't used; we have no idea what we should be opening
        fprintf(stderr, "$HOME wasn't set; --file must be used\n");
        throw FailEx();
      }

      if (!arg_name && (arg_op == OP_EMIT || arg_op == OP_EDIT || arg_op == OP_DELETE)) {
        fprintf(stderr, "An entry must be specified\n");
        throw FailEx();
      }

      if (arg_name && !arg_casesensative) {
        // automatically be case sensative of arg_name contains any uppercase chars
        const char* p = arg_name;
        while (*p)
          if (isupper(*p++)) {
            arg_casesensative = true;
            break;
          }
      }

#ifndef X_DISPLAY_MISSING
      if (arg_xclip && !XDisplayName(arg_display)) {
        fprintf(stderr, "$DISPLAY isn't set; use --display\n");
        throw FailEx();
      }

      // map arg_selection to a descriptive text string
      // NOTE this must match the similar code in emit()
      switch (tolower(arg_selection[0])) {
        case 'b': case '0': xsel_names = "both X primary selection and clipboard"; break;
        case 'p': case '1': xsel_names = "X primary selection"; break;
        case 's': case '2': xsel_names = "X secondary selection"; break;
        case 'c': xsel_names = "clipboard"; break;
        default:
          fprintf(stderr,"Unsupported selection: %s\n", arg_selection);
          throw FailEx();
      }
#endif

      // mess around with stdout and outfile so they are intelligently selected
      // what we want is usages like "pwsafe | less" to work correctly
      if (arg_output) {
        outfile = fopen(arg_output,"w");
      } else if (!isatty(STDOUT_FILENO) && isatty(STDERR_FILENO)) {
        // if stdout is not a tty but stderr is, use stderr to interact with the user, but still write the output to stdout
        int outfd = dup(STDOUT_FILENO);
        dup2(STDERR_FILENO,STDOUT_FILENO);
        outfile = fdopen(outfd,"w");
      } else {
        // use stdout
        outfile = fdopen(dup(STDOUT_FILENO),"w");
      }
      if (!outfile) {
        fprintf(stderr, "Can't open %s: %s\n", arg_output, strerror(errno));
        throw FailEx();
      }
      // from this point on stdout points to something we can interact with the user on, and outfile points to where we should put our output
 

      // seed the random number generator
      char rng_filename[PATH_MAX+1];
      if (RAND_file_name(rng_filename,sizeof(rng_filename))) {
        int rc = RAND_load_file(rng_filename,-1);
        if (rc) {
          if (arg_verbose > 0) printf("rng seeded with %d bytes from %s\n", rc, rng_filename);
        } else {
          if (arg_verbose >= -1) // two -q/--quiet's will turn this msg off
            fprintf(stderr, "WARNING: %s unable to seed rng from %s\n", program_name, rng_filename);
        }
      } else {
        rng_filename[0] = '\0';
        if (arg_verbose >= -1)
          fprintf(stderr, "WARNING: %s unable to seed rng. Check $RANDFILE.\n", program_name);
      }

#ifndef X_DISPLAY_MISSING
      if (arg_verbose >= 0 && (arg_password || arg_username) && (arg_echo || arg_xclip))
        printf("Going to %s %s to %s\n", arg_xclip?"copy":"print", arg_password&&arg_username?"login and password":arg_password?"password":"login", arg_xclip?xsel_names:"stdout");
#else
      if (arg_verbose >= 0 && (arg_password || arg_username) && (arg_echo))
        printf("Going to print %s to stdout\n", arg_password&&arg_username?"login and password":arg_password?"password":"login");
#endif
      DB::Init();

      switch (arg_op) {
      case OP_NOP:
        fprintf (stderr, "%s - No command specified\n", program_name);
        usage(true);
        break;
      case OP_CREATEDB:
        DB::createdb(arg_dbname);
        break;
      case OP_EXPORTDB:
      case OP_MERGEDB:
      case OP_PASSWD:
      case OP_LIST:
      case OP_EMIT:
      case OP_ADD:
      case OP_EDIT:
      case OP_DELETE:
        {
          DB db(arg_dbname);
          try {
            switch (arg_op) {
              // NOTE it is correct not to have a OP_NOP and OP_CREATEDB case here. They are handled above in the outer switch and cannot reach this code
              // however g++ doesn't realize this, and -Wall spits out a warning that those two enum values aren't handled in this switch. So they are here
              // only to quiet g++, and not because they make any sense in the program flow.
            case OP_NOP: case OP_CREATEDB: break; // unreachable, but makes g++ -Wall happy
            case OP_EXPORTDB:
              db.exportdb();
              break;
            case OP_MERGEDB:
              {
                DB db2(arg_mergedb);
                db.mergedb(db2);
              }
              break;
            case OP_PASSWD:
              db.passwd();
              break;
            case OP_LIST:
              db.list(arg_name);
              break;
            case OP_EMIT:
              db.emit(arg_name, arg_username, arg_password, arg_twice);
              break;
            case OP_ADD:
              db.add(arg_name);
              if (!arg_name) {
                // let them add more than one without having to reenter the passphrase
                while (getyn("Add another? [n] ", false))
                  db.add(NULL);
              }
              break;
            case OP_EDIT:
              db.edit(arg_name);
              break;
            case OP_DELETE:
              db.del(arg_name);
              break;
            // cases OP_NOP and OP_CREATEDB were handled earlier, above
            }

            // backup and save if changes have occured
            if (db.is_changed()) {
              if (arg_verbose > 0) printf("saving changes to %s\n", db.dbname);
              if (!(db.backup() && db.save()))
                throw FailEx();
            }
              
          } catch (const FailEx&) {
            // try and restore database from backup if a backup was successfully created
            db.restore();
            throw;
          }
        }
        break;
      }

      // first try and close outfile with error checking
      if (outfile) {
        if (fclose(outfile)) {
          fprintf(stderr, "Can't write/close output: %s", strerror(errno));
          outfile = NULL;
          throw FailEx();
        }
        outfile = NULL;
      }

      // save the rng seed for next time
      if (rng_filename[0]) {
        int rc = RAND_write_file(rng_filename);
        if (arg_verbose > 0) printf("wrote %d bytes to %s\n", rc, rng_filename);
      } // else they already got an error above when we tried to read rng_filename
   
      // and we are done
      throw ExitEx(0);
      
    } catch (const FailEx&) {
      throw ExitEx(1);
    }
  } catch (const ExitEx& ex) {
#ifndef X_DISPLAY_MISSING
    if (xdisplay)
      XCloseDisplay(xdisplay);
#endif
    if (outfile)
      fclose(outfile);
    
    return ex.rc;
  }
}

// Set all the option flags according to the switches specified.
// Return the index of the first non-option argument.
static int parse(int argc, char **argv) {
  int c;

  while ((c = getopt_long (argc, argv,
          "l"   // long listing
          "a"   // add
          "e"   // edit
//          "F:"  // config
          "A:"  // askpass program
          "f:"  // file
          "I"   // case sensative
          "E"   // echo
          "o:"  // output
          "u"   // username
          "p"   // password
          "t"   // twice
#ifndef X_DISPLAY_MISSING
          "x"   // xclip
          "d:"  // display
          "s:"  // x selection
          "G:"  // ignore
#endif
          "q"   // quiet
          "v"   // verbose
          "g"   // debug
          "h"   // help
          "V",  // version
          long_options, (int *) 0)) != EOF)
  {
    switch (c) {
      case 'C':
        if (arg_op == OP_NOP)
          arg_op = OP_CREATEDB;
        else
          usage(true);
        break;
      case 'E'&31:
        if (arg_op == OP_NOP)
          arg_op = OP_EXPORTDB;
        else
          usage(true);
        break;
      case 'M'&31:
        if (arg_op == OP_NOP) {
          arg_op = OP_MERGEDB;
          arg_mergedb = optarg;
        } else
          usage(true);
        break;
      case 'P':
        if (arg_op == OP_NOP)
          arg_op = OP_PASSWD;
        else
          usage(true);
        break;
      case 'L':
        if (arg_op == OP_NOP)
          arg_op = OP_LIST;
        else
          usage(true);
        break;
      case 'a':
        if (arg_op == OP_NOP)
          arg_op = OP_ADD;
        else
          usage(true);
        break;
      case 'e':
        if (arg_op == OP_NOP)
          arg_op = OP_EDIT;
        else
          usage(true);
        break;
      case 'D':
        if (arg_op == OP_NOP)
          arg_op = OP_DELETE;
        else
          usage(true);
        break;
//      case 'F':
//        arg_config = optarg;
//        break;
      case 'A':
        arg_askpass = optarg;
        break;
      case 'f':
        arg_dbname = optarg;
        break;
      case 'I':
        arg_casesensative = true;
        break;
      case 'l':
        if (arg_op == OP_NOP || arg_op == OP_LIST) {
          arg_op = OP_LIST;
          arg_details = true;
        } else
          usage(true);
        break;
      case 'V'&31:
        switch (strtol(optarg, 0, 10)) {
          case 1: arg_dbversion = VERSION_1_7; break;
          case 2: arg_dbversion = VERSION_2_0; break;
          default: usage(true);
        }
        break;
      case 'o':
        arg_output = optarg;
        // -o implies -e
        // falls through
      case 'E':
        arg_echo = true; 
#ifndef X_DISPLAY_MISSING
        arg_xclip = false;
#endif
        break;
      case 'u':
        arg_username = true;
        break;
      case 'p':
        arg_password = true;
        break;
      case 't':
        arg_twice = true;
        break;
#ifndef X_DISPLAY_MISSING
      case 'd':
        arg_display = optarg;
        arg_xclip = true; arg_echo = false; // -d implies -x
        break;
      case 's':
        arg_selection = optarg; // we can't parse it until we open X
        // -s implies -x
        // falls through
      case 'x':
        arg_xclip = true; arg_echo = false;
        break;
      case 'G':
        arg_ignore.insert(optarg);
        break;
#endif
      case 'q':
        arg_verbose--;
        break;
      case 'v':
        arg_verbose++;
        break;
      case 'g': // think gcc -g (since -d is taken)
        arg_debug++;
        break;
      case 'V':
        printf("pwsafe %s\n", VERSION);
        throw ExitEx(0);
      case 'h':
        usage(false);
        throw ExitEx(0);
      case ':':
      case '?':
        // the message getopt() printed out is good enough
        throw FailEx();
      default:
        usage(true);
    }
  }

  return optind;
}


static void usage(bool fail) {
  if (!fail)
    printf("%s - commandline tool compatible with Counterpane's Passwordsafe\n", program_name);
  else
    fprintf(stderr,"\n");
  fprintf(fail?stderr:stdout,"Usage: %s [OPTION] command [ARG]\n", program_name);
  fprintf(fail?stderr:stdout,
        "Options:\n"
//        "  -F, --config=CONFIG_FILE   specify a configuration (defaults is ~/.pwsaferc + /etc/pwsaferc)\n"
        "  -f, --file=DATABASE_FILE   specify the database file (default is ~/.pwsafe.dat)\n"
        "  -I, --case                 perform case sensative matching\n"
        "  -A=<program>               use external program to ask for password (e.g. ssh-askpass)\n"
        "  -l                         long listing (show username & notes)\n"
        "  -u, --username             emit username of listed account\n"
        "  -p, --password             emit password of listed account\n"
        "  -t, --twice                emit twice for hungry chrome\n"
        "  -E, --echo                 force echoing of entry to stdout\n"
        "  -o, --output=FILE          redirect output to file (implies -E)\n"
        "  --dbversion=[1|2]          specify database file version (default is 2)\n"
#ifndef X_DISPLAY_MISSING
        "  -x, --xclip                force copying of entry to X selection\n"
        "  -d, --display=XDISPLAY     override $DISPLAY (implies -x)\n"
        "  -s, --selection={Primary,Secondary,Clipboard,Both} select the X selection effected (implies -x). Default is both primary and clipboard.\n"
        "  -G, --ignore=NAME@HOST     add NAME@HOST to set of windows that don't receive the selection. Either NAME or @HOST can be omitted. (default is xclipboard, wmcliphist, klipper and <unknown>)\n"
#endif
        "  -q, --quiet                print no extra information\n"
        "  -v, --verbose              print more information (can be repeated)\n"
        "  -h, --help                 display this help and exit\n"
        "  -V, --version              output version information and exit\n"
        "Commands:\n"
        "  --createdb                 create an empty database\n"
        "  --exportdb                 dump database as text\n"
        "  --mergedb=DATABASE_FILE2   merge entries from FILE2 into database\n"
        "  --passwd                   change database passphrase\n"
        "  [--list] [REGEX]           list all [matching] entries. If -u and/or -p are given, only one entry may match\n"
        "  -a, --add [NAME]           add an entry\n"
        "  -e, --edit REGEX           edit an entry\n"
        "  --delete NAME              delete an entry\n"
      );
  if (fail)
    throw FailEx();
}

static const char* pwsafe_strerror(int err) {
  switch (err) {
    case 0:
      return "Truncated pwsafe database file";
    case PWSAFE_ERR_INVALID_DB:
      return "Invalid pwsafe database file";
    default:
      return strerror(err);
  }
}

// get input from the user, possibly turning echo off
static secstring getin(const char * prompt, const secstring& default_, bool echooff)
{
  struct termios tio;
  if (echooff) {
    // turn off echo
    tcgetattr(STDIN_FILENO, &tio);
    {
      struct termios new_tio = tio;
      new_tio.c_lflag &= ~(ECHO);
      tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_tio); // FLUSH so they don't get into the habit of typing ahead their passphrase
    }
  }

  // prompt and read the next line of input
  std::cout << prompt << std::flush;
  std::string x;
  std::getline(std::cin, x); // NOTE: consumes the LF but strips it from the result

  // restore echo if we turned it off
  if (echooff) {
    tcsetattr(STDIN_FILENO, TCSANOW, &tio);

    // and echo a linefeed since the user's <Enter> was not echoed
    std::cout << std::endl;
  }

  // do we have a line?
  if (!std::cin.fail() && !std::cin.eof()) {
    secstring xx(x.c_str(), x.size());
    x.clear(); // x is a local; I'm not sure this does much. what we really want here is a memset(0) of the buffer
    return xx.empty() ? default_ : xx;
  } else {
    // EOF/^d; abort
    throw FailEx();
  }
}

// get a password from the user
static secstring getpw(const std::string& prompt) {
  // use askpass binary if requested
  if (arg_askpass) {
    FILE* pipe = popen(arg_askpass, "r");
    if (!pipe) {
      fprintf(stderr, "ERROR: cannot run askpass binary %s: %s\n", arg_askpass, strerror(errno));
      throw FailEx();
    }
    char buffer[2048];
    errno = 0;
    if (fgets(buffer, sizeof(buffer), pipe) == NULL) {
      // we must distingush between an empty password and a failure. assume an empty password unless errno was set
      if (errno) {
        fprintf(stderr, "ERROR: cannot read password from askpass binary %s: %s\n", arg_askpass, strerror(errno));
        throw FailEx();
      }
      buffer[0] = '\0';
    }
    // Drop last char (LF) from buffer if it's not empty
    size_t pwlen = strlen(buffer);
    if (pwlen>0 && buffer[pwlen-1] == '\n') {
      buffer[pwlen-1] = '\0';
    }
    secstring xx(buffer);
    memset(buffer, 0, sizeof(buffer));
    int returnCode = pclose(pipe);
    if (returnCode) {
      fprintf(stderr, "ERROR: askpass binary returned %d\n", returnCode);
      throw FailEx();
    }
    return xx;
  }

  // no askpass? Use terminal
  return getin(prompt.c_str(), "", true);
}

static secstring gettxt(const secstring& prompt, const secstring& default_="") {
  return getin(prompt.c_str(), default_, false);
}

static char get1char(const char*const prompt, const int def_val) {
  struct termios tio;
  tcgetattr(STDIN_FILENO, &tio);
  {
    termios new_tio = tio;
    new_tio.c_lflag &= ~(ICANON);
    // now that we turn ICANON off we *must* set VMIN=1 or on sparc the read() buffers 4 at a time
    new_tio.c_cc[VMIN] = 1;
    new_tio.c_cc[VTIME] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
  }

  while (true) {
    std::cout << prompt << std::flush;
    char x = 0;
    std::cin.get(x);

    // NOTE cin.eof() doesn't return true here for ^D b/c cin.get() is raw input. ^D must be checked for and handled explicitly
    if (std::cin.fail() || (x == tio.c_cc[VEOF])) {
      // EOF; restore and fail
      tcsetattr(STDIN_FILENO, TCSANOW, &tio);
      throw FailEx();
    }

    switch (x) {
    case '\r':
      std::cout << std::endl;
      // falls through
    case '\n':
      if (def_val >= 0) {
        tcsetattr(STDIN_FILENO, TCSANOW, &tio);
        return def_val;
      }
      // else there is no default and the user must press a proper char
      break;
    default:
      std::cout << std::endl;
      tcsetattr(STDIN_FILENO, TCSANOW, &tio);
      return x;
    }
    // if we get this far the user didn't answer, and we loop and reprompt them
  }
}

static bool getyn(const char*const prompt, const int def_val) {
  while (true) {
    char c = get1char(prompt, def_val>0?'y':def_val==0?'n':-1);
    switch (tolower(c)) {
    case 'y':
      return true;
    case 'n':
      return false;
    // default: prompt again until we get a good answer
    }
  }
}

static secstring random_password() {
  // here I implement the 'easyvision' mode of pwsafe 1.9.x where the resulting ascii has nice legibility properties for those who copy these by hand
  const static char all_alphanum[] = "abcdefghijklmnopqrstuvwxyz"
                                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                "0123456789";
  const static char easyvision_alphanum[] = "abcdefghijkmnopqrstuvwxyz"
                                       "ABCDEFGHJKLMNPQRTUVWXY"
                                       "346789";
  const static char easyvision_symbol[] = "+-=_@#$%^&<>/~\\?";
  const static char hex_only[] = "0123456789abcdef";
  const static char digits_only[] = "0123456789";


  int entropy_needed = 20*8; // enough for proper initialization of a SHA1 hash, and enough for proper direct keying of 128-bit block ciphers
  int type = 0;
  while (true) {
    const char* type_name = "";
    const char* sets[2] = { "", "" };
    int entropy_per_char;
    bool one_char_from_each_type = true;
    switch (type) {
      case 0: 
        type_name = "alpha/digit/symbol";
        sets[0] = all_alphanum;
        sets[1] = easyvision_symbol;
        entropy_per_char = 628; // 100 * log2(26+26+10+16) = log2(78); best case
        break;
      case 1:
        type_name = "alpha/digit";
        sets[0] = all_alphanum;
        entropy_per_char = 595;
        break;
      case 2:
        type_name = "easy-to-read alpha/digit";
        sets[0] = easyvision_alphanum;
        entropy_per_char = 555; // 100 * log2(25+22+10) = log2(57); worse case
        break;
      case 3:
        type_name = "easy-to-read alpha/digit/symbol";
        sets[0] = easyvision_alphanum;
        sets[1] = easyvision_symbol;
        entropy_per_char = 597;
        break;
      case 4:
        type_name = "digits only";
        sets[0] = digits_only;
        entropy_per_char = 332; // 100 * log2(10)
        one_char_from_each_type = false;
        break; 
      case 5:
        type_name = "hex digits only";
        sets[0] = hex_only;
        entropy_per_char = 400; // 100 * log2(16)
        one_char_from_each_type = false;
        break; 
      default:
        // wrap around back to type 0
        type = 0;
        continue;
    }

    const int set0_chars = strlen(sets[0]);
    const int total_chars = set0_chars + strlen(sets[1]);
    
    // But we are not going to generate all possible passwords because we are going to exclude those that don't have at least one char from each type, so that reduces the entropy_per_char
    // if originally we had 2^(num_chars * entropy_per_char) possible passwords, and we exclude (in the worst case) (and double-counting those passwords that have two types of char missing)
    // (57-25)/57 ^ num_chars + (57-22)/57 ^ num_chars + (57-10)/57 ^ num_chars of these, we reduce the bits of entropy per char by
    // log2(57)-log2(57-25) + log2(57)-log2(57-22) + log2(57)-log2(57-10) = 1.82 pessimist bits/char
    if (one_char_from_each_type)
      entropy_per_char -= 182;
  
    const int num_chars = 1+100*entropy_needed/entropy_per_char; // we want 20*8 bits of entropy in our password (thus good enough to create good SHA1 hashes/to key 128-bit key secret key algo's); +1 is in lou of rounding the division properly

    secstring pw;
    bool got_upper, got_lower, got_num, got_sym;
    do {
      pw.erase();

      got_upper = false, got_lower = false, got_num = false, got_sym = false;
      for (int i=0; i<num_chars; i++) {
        unsigned char idx;
        do {
          if (!RAND_bytes(&idx,1)) {
            fprintf(stderr, "Can't get random data: %s\n", ERR_error_string(ERR_get_error(), NULL));
            throw FailEx();
          }
          idx &= 0x7f; // might as well strip off the upper bit since total_chars is never more than 64, and such a stripping doesn't change the distribution
        } while (idx >= total_chars);
        
        char c;
        if (idx < set0_chars)
          c = sets[0][idx];
        else
          c = sets[1][idx-set0_chars];

        pw += c;
          
        if (islower(c)) got_lower = true;
        else if (isupper(c)) got_upper = true;
        else if (isdigit(c)) got_num = true;
        else got_sym = true;
      }
    } while (one_char_from_each_type && (!got_lower || !got_upper || !got_num || (sets[1][0] && !got_sym))); // some systems want one of each type of char in the password, so might as well do it all the time, even though it is a tiny bit less random this way (but we already took that into account in entropy_per_char)

    // see what the user thinks of this one
    char ent_buf[24];
    snprintf(ent_buf, sizeof(ent_buf), "%d", entropy_needed);
    ent_buf[sizeof(ent_buf)-1] = '\0';
    char len_buf[24];
    snprintf(len_buf, sizeof(len_buf), "%zd", pw.length());
    len_buf[sizeof(len_buf)-1] = '\0';
    switch (tolower(get1char("Use "+pw+"\ntype "+type_name+", length "+len_buf+", "+ent_buf+" bits of entropy [y/N/ /+/-/q/?] ? ", 'n'))) {
      case 'y':
        return pw;
      case 'q':
        return "";
      case ' ':
        type++;
        break;
      case '-':
        if (entropy_needed > 128)
          entropy_needed -= 32;
        else if (entropy_needed > 64)
          entropy_needed -= 16;
        else if (entropy_needed > 32)
          entropy_needed -= 8;
        // else you can't go any lower
        break;
      case '+': case '=':
        if (entropy_needed < 64)
          entropy_needed += 8;
        else if (entropy_needed < 128)
          entropy_needed += 16; // so we can hit 112, the magic number for WEP keys
        else
          entropy_needed += 32;
        break;
      case '?': case 'h':
        printf("Commands:\n"
               "  Y      Yes, accept this password\n"
               "  N      No, generate another password of same type\n"
               "  <space> Cycle through password types\n"
               "  -      Lower the entropy & password length\n"
               "  +      Raise the entropy & password length\n"
               "  Q      Quit\n"
               "  ?      Help\n");
        continue;
      // default: show another password
    }
  }
}

static secstring enter_password(const char* prompt1, const char* prompt2) {
  while (true) {
    secstring pw1 = getpw(prompt1);
    if (pw1.empty()) {
      if (getyn("Generate random password? [y] ", true)) {
        pw1 = random_password();
        if (!pw1.empty())
          return pw1;
        else
          continue; // back to entering by hand for them (perhaps they want to copy only a subset of the original pw)
      } // else let them have an empty password, though they'll have to enter it twice
    }
    secstring pw2 = getpw(prompt2);
    if (pw1 == pw2) {
      return pw1;
    }
    printf("Passwords do not match\n");
  }
}

// print txt to outfile / copy to X selection
static void emit(const secstring& name, const char*const what, const secstring& txt) {
  if (arg_echo) {
    if (arg_verbose >= 0 && isatty(fileno(outfile)))
      fprintf(outfile,"%s for %s: ", what, name.c_str()); // if we are printing to the tty then we can be more verbose
    fprintf(outfile,"%s\n", txt.c_str());
  }
#ifndef X_DISPLAY_MISSING
  else if (arg_xclip) {
    if (!xdisplay) // only open X once, since it is slow
      xdisplay = XOpenDisplay(arg_display);

    if (!xdisplay) {
      fprintf(stderr,"Can't open display: %s\n", XDisplayName(arg_display));
      throw FailEx();
    }

    const Atom CLIPBOARD = XA_CLIPBOARD(xdisplay); // optimize by fetching this one only once

    Atom xsel1 = 0, xsel2 = 0; // X11 Atom representing X selections and clipboard
    int num_xsel = 1; // number of valid xsel*

    // map arg_selection to X11 Atom(s)
    switch (tolower(arg_selection[0])) {
      case 'b': case '0': xsel1 = XA_PRIMARY; xsel2 = CLIPBOARD; num_xsel = 2; break;
      case 'p': case '1': xsel1 = XA_PRIMARY; break;
      case 's': case '2': xsel1 = XA_SECONDARY; break;
      case 'c': xsel1 = CLIPBOARD; break;
      default:
        fprintf(stderr,"Unsupported selection: %s\n", arg_selection);
        throw FailEx();
    }

    char* stxt1 = XGetAtomName(xdisplay,xsel1);
    char* stxt2 = (xsel2?XGetAtomName(xdisplay,xsel2):NULL);

    Window xwin = XCreateSimpleWindow(xdisplay, DefaultRootWindow(xdisplay), 0,0,1,1,0,0,0);
    XSelectInput(xdisplay, xwin, PropertyChangeMask);
    
    { // the X11 ICCCM section 3.2.1 says we must synthesize an event in order to get a timestamp to use with XSetSelectionOwner() instead of using CurrentTime, so we will take the time from the WM_COMMAND event generated inside XSetWMProperties()
      const char*const argv[2] = { program_name, NULL }; // lie about our argv so that we don't expose any semi-sensative commandline options
      XTextProperty winname = { reinterpret_cast<unsigned char*>(const_cast<char*>(program_name)), XA_STRING, 8, strlen(program_name) };
      XSetWMProperties(xdisplay, xwin, &winname,NULL, const_cast<char**>(argv),1, NULL,NULL,NULL); // also init's WM_CLIENT_MACHINE
    }

    Time timestamp = 0;
    Window prev_requestor = 0, prevprev_requestor = 0;
    const int xfd = ConnectionNumber(xdisplay);

    struct termios tio;
    tcgetattr(STDIN_FILENO, &tio);
    {
      termios new_tio = tio;
      new_tio.c_lflag &= ~(ICANON);
      // now that we turn ICANON off we *must* set VMIN=1 or on sparc the read() buffers 4 at a time
      new_tio.c_cc[VMIN] = 1;
      new_tio.c_cc[VTIME] = 0;
      // turn off echo too; no need to show them the char they pressed
      new_tio.c_lflag &= ~(ECHO);
      tcsetattr(STDIN_FILENO, TCSANOW, &new_tio);
    }

    fd_set in;
    FD_ZERO(&in);
    bool done = false;

    while (xsel1 || xsel2) {
      if (timestamp && FD_ISSET(STDIN_FILENO, &in)) {
        char x;
        ssize_t rc = read(STDIN_FILENO,&x,1);
        done |= (rc == 1);
      }

      if (done) {
        // we are done
        if (xsel1) {
          XSetSelectionOwner(xdisplay, xsel1, None, timestamp);
          xsel1 = 0;
        }
        if (xsel2) {
          XSetSelectionOwner(xdisplay, xsel2, None, timestamp);
          xsel2 = 0;
        }
      }

      while (XPending(xdisplay) > 0) {
        XEvent xev;
        XNextEvent(xdisplay,&xev);

        if (xev.type == PropertyNotify) {
          if (!timestamp && xev.xproperty.window == xwin && xev.xproperty.state == PropertyNewValue && xev.xproperty.atom == XA_WM_COMMAND) {
            timestamp = xev.xproperty.time; // save away the timestamp; that's all we really wanted
            XSetSelectionOwner(xdisplay, xsel1, xwin, timestamp);
            if (xsel2)
              XSetSelectionOwner(xdisplay, xsel2, xwin, timestamp);
            if (xsel2 && XGetSelectionOwner(xdisplay, xsel2) != xwin) {
              fprintf(stderr, "Unable to own X selection %s\n", stxt2);
              xsel2 = 0;
              num_xsel--;
            }
            if (XGetSelectionOwner(xdisplay, xsel1) != xwin) {
              fprintf(stderr, "Unable to own X selection %s\n", stxt1);
              xsel1 = xsel2;
              if (stxt1) XFree(stxt1);
              stxt1 = stxt2;
              xsel2 = 0; stxt2 = NULL;
              num_xsel--;
            }

            // let the user know
            if (xsel1 && xsel2) {
              if (arg_verbose >= 0)
                printf("You are ready to paste the %s for %s from %s and %s\nPress any key when done\n", what, name.c_str(), stxt1, stxt2);
            } else if (xsel1) {
              if (arg_verbose >= 0)
                printf("You are ready to paste the %s for %s from %s\nPress any key when done\n", what, name.c_str(), stxt1);
            }
          }
        }
        else if (xev.type == SelectionRequest) {
          Atom prop = xev.xselectionrequest.property;
          if (prop == None)
            prop = xev.xselectionrequest.target; // an old-style client
     
          bool fakeout = false;

          // don't answer if the timestamp is too early or too late
          if (!timestamp || (xev.xselectionrequest.time!=CurrentTime && xev.xselectionrequest.time < timestamp))
            fakeout = true;
          // don't answer if we don't actually own it
          if ((!xsel1 || xev.xselectionrequest.selection != xsel1) && (!xsel2 || xev.xselectionrequest.selection != xsel2))
            fakeout = true;
          // don't answer if we aren't the owner
          if (xev.xselectionrequest.owner != xwin)
            fakeout = true;

          if (!fakeout) {
            // see what they want exactly
            if (xev.xselectionrequest.target == XA_TARGETS(xdisplay)) {
              // tell them what we can supply
              const Atom targets[] = { XA_TARGETS(xdisplay), XA_TIMESTAMP(xdisplay), XA_TEXT(xdisplay), XA_STRING }; // TODO maybe XA_UTF8_STRING(xdisplay) ? XA_STRING is Latin-1 which is not really what we send when the locale is UTF-8, as it often is these days
              XChangeProperty(xdisplay, xev.xselectionrequest.requestor, prop, XA_ATOM, 32, PropModeReplace, reinterpret_cast<const unsigned char*>(&targets), sizeof(targets)/sizeof(targets[0]));
            }
            else if (xev.xselectionrequest.target == XA_TIMESTAMP(xdisplay)) {
              // the ICCCM v2 section 2.6.2 says the type of the TIMESTAMP property should be INTEGER
              XChangeProperty(xdisplay, xev.xselectionrequest.requestor, prop, XA_INTEGER, 32, PropModeReplace, reinterpret_cast<const unsigned char*>(&timestamp), 1);
            }
            else if (xev.xselectionrequest.target == XA_TEXT(xdisplay) ||
                xev.xselectionrequest.target == XA_STRING) {
              // be very verbose about who is asking for the selection---it could catch a clipboard sniffer
              const char*const selection = xev.xselectionrequest.selection == xsel1 ? stxt1 : stxt2; // we know xselectionrequest.selection is xsel1 or xsel2 already, so no need to be more paranoid

              // walk up the tree looking for a client window
              Window w = xev.xselectionrequest.requestor;
              while (true) {
                XTextProperty tp;
                int rc = XGetTextProperty(xdisplay, w, &tp, XA_WM_COMMAND);
                if (tp.value) XFree(tp.value), tp.value = NULL;
                if (!rc) {
                  rc = XGetWMName(xdisplay, w, &tp);
                  if (tp.value) XFree(tp.value), tp.value = NULL;
                }
                if (rc)
                  break;
                Window p = XmuClientWindow(xdisplay, w);
                if (w != p)
                  break; // this means we've found it
                Window parent;
                Window root;
                Window* children = NULL;
                unsigned int numchildren;
                if (XQueryTree(xdisplay, w, &root, &parent, &children, &numchildren) && children) // unfortunately you can't pass in NULLs to indicate you don't care about the children
                  XFree(children);
                if (parent == root)
                  break; // we shouldn't go any further or we will read the properties of the root
                w = parent;
              }

              const char* requestor = "<unknown>";
              XTextProperty nm;
              if ((XGetWMName(xdisplay, w, &nm) && nm.encoding == XA_STRING && nm.format == 8 && nm.value) ||
                  (((nm.value?(XFree(nm.value),nm.value=NULL):0), XGetTextProperty(xdisplay, w, &nm, XA_WM_COMMAND)) && nm.encoding == XA_STRING && nm.format == 8 && nm.value)) // try getting WM_COMMAND if we can't get WM_NAME
                requestor = reinterpret_cast<const char*>(nm.value);

              const char* host = "<unknown>";
              XTextProperty cm;
              if (XGetWMClientMachine(xdisplay, w, &cm) && cm.encoding == XA_STRING && cm.format == 8)
                host = reinterpret_cast<const char*>(cm.value);

              if (arg_ignore.find(requestor) != arg_ignore.end() ||
                  arg_ignore.find(std::string("@")+host) != arg_ignore.end() ||
                  arg_ignore.find(requestor+std::string("@")+host) != arg_ignore.end()) {
                fakeout = true;
              }

              if (xev.xselectionrequest.requestor != prev_requestor && xev.xselectionrequest.requestor != prevprev_requestor) { // programs like KDE's Klipper re-request every second, so it isn't very useful to print out multiple times
                if (!fakeout) {
                  if (arg_verbose >= 0)
                    printf("Sending %s for %s to %s@%s via %s\n", what, name.c_str(), requestor, host, selection);
                } else if (arg_verbose > 0) 
                  printf("Ignoring request from %s@%s\n", requestor, host);
              }

              if (nm.value) XFree(nm.value);
              if (cm.value) XFree(cm.value);

              if (!fakeout) {
                XChangeProperty(xdisplay, xev.xselectionrequest.requestor, prop, XA_STRING, 8, PropModeReplace, reinterpret_cast<const unsigned char*>(txt.c_str()), txt.length());
                done = true;
              }

              prevprev_requestor = prev_requestor;
              prev_requestor = xev.xselectionrequest.requestor;
            }
            else {
              // a target I don't handle
              fakeout = true;
            }
          }

          if (fakeout)
            prop = None; // indicate no answer

          XEvent resp;
          resp.xselection.property = prop;
          resp.xselection.type = SelectionNotify;
          resp.xselection.display = xev.xselectionrequest.display;
          resp.xselection.requestor = xev.xselectionrequest.requestor;
          resp.xselection.selection = xev.xselectionrequest.selection;
          resp.xselection.target = xev.xselectionrequest.target;
          resp.xselection.time = xev.xselectionrequest.time;
          XSendEvent(xdisplay, xev.xselectionrequest.requestor, 0,0, &resp);
        }
        else if (xev.type == SelectionClear) {
          // some other program is taking control of the selection, so we are done
          // don't answer if the timestamp is too early or too late
          if (!timestamp || (xev.xselectionclear.time != CurrentTime && xev.xselectionclear.time < timestamp)) {
            // ignore it; timestamp is out of bounds
          } else {
            if (xsel1 && xev.xselectionclear.selection == xsel1) {
              if (xsel1 != CLIPBOARD && xsel2) { // a clipboard manager application will always take control of the XA_CLIPBOARD immediately, so don't worry about that
                XSetSelectionOwner(xdisplay, xsel2, None, timestamp);
                xsel2 = 0;
              }
              xsel1 = 0;
            }
            if (xsel1 && xev.xselectionclear.selection == xsel2) {
              if (xsel2 != CLIPBOARD && xsel1) {
                XSetSelectionOwner(xdisplay, xsel1, None, timestamp);
                xsel1 = 0;
              }
              xsel2 = 0;
            }
          }
        } else {
          // it is some event we don't care about
        }
      }

      // wait for either a keystroke or an x event
      if (!done && (xsel1 || xsel2)) {
        FD_ZERO(&in);
        FD_SET(STDIN_FILENO, &in);
        FD_SET(xfd, &in);
        int rc = select(std::max(STDIN_FILENO, xfd)+1, &in, NULL, NULL, NULL);
        if (rc < 0 ) {
          tcsetattr(STDIN_FILENO, TCSANOW, &tio);
          throw FailEx();
        }
        if (rc == 0)
          FD_ZERO(&in);
      }
    }

    tcsetattr(STDIN_FILENO, TCSANOW, &tio);

    if (arg_verbose > 1) printf("X selection%s cleared\n",(num_xsel>1?"s":""));

    if (stxt1) XFree(stxt1);
    if (stxt2) XFree(stxt2);
  }
#endif // X_DISPLAY_MISSING
}

// pretty print notes to tty, prefixing each line with "> "
static void emit_notes(const secstring& notes) {
  if (!notes.empty()) {
    const char* p = notes.c_str();
    while (*p) {
      const char* q = p;
      while (*q && *q != '\n' && *q != '\r') q++;
      fwrite("> ", 1, 2, outfile);
      fwrite(p, 1, q-p, outfile);
      fwrite("\n", 1, 1, outfile);
      while (*q && (*q == '\n' || *q == '\r')) q++;
      p = q;
    }
  }
}

// ---- Block class -------------------------------

Block::~Block() {
  zero();
}

void Block::zero() {
  memset(block,0,sizeof(block));
}
  
void Block::makeLE(unsigned char b[8]) {
  if (0x1234 == ntohl(0x1234)) {
    // this is a big-endian system; put the 8 bytes data in little-endian order
    for (int j=0; j<2; j++) {
      std::swap(b[j],b[3-j]);
      std::swap(b[4+j],b[7-j]);
    }
  }
}

Block& Block::operator ^=(const Block& b) {
  block[0] ^= b.block[0];
  block[1] ^= b.block[1];
  return *this;
}

void Block::putInt32AndType(int32_t x, uint8_t t) {
  block[0] = x;
  block[1] = t; // because we are always byte-ordered correctly, we can just do this
}

int32_t Block::getInt32() const {
  return block[0]; // because we are always byte-ordered correctly, we can just do this
}

uint8_t Block::getType() const {
  return block[1] & 0xff; // because we are always byte-ordered correctly, we can just do this
}

void Block::read(const unsigned char* data, int len) {
  if (static_cast<size_t>(len) < sizeof(block))
    memset(block,0,sizeof(block));
  memcpy(block,data,std::min(int(sizeof(block)),len));
  makeLE(reinterpret_cast<unsigned char*>(block));
}

void Block::write(unsigned char data[8]) const {
  memcpy(data,block,8);
  makeLE(data);
}

bool Block::read(FILE* f) {
  unsigned char data[8];
  errno = 0;
  const bool rc = fread(data, 1,sizeof(data), f) == sizeof(data);
  if (rc)
    read(data,8);
  return rc;
}

bool Block::write(FILE* f) const {
  unsigned char data[8];
  write(data);
  bool rc = fwrite(data, 1,sizeof(data), f) == sizeof(data);
  return rc;
}
    

// ---- DB class -------------------------------------------------------

void DB::Init() {
  Entry::Init();
}

DB::DB(const char* n, Version v) : 
  version(v), 
  opened(false), changed(false), backedup(false), overwritten(false),
  dbname_str(n), dbname(dbname_str.c_str())
{
  header = new Header();
}

DB::~DB() {
  delete header;
}

void DB::createdb(const char* dbname) {
  if (arg_verbose > 0) printf("creating %s\n", dbname);
  
  // be sure not to overwrite an existing file
  struct stat s;
  if (!stat(dbname, &s)) {
    fprintf(stderr, "%s already exists\n", dbname);
    throw FailEx();
  }

  DB db(dbname, arg_dbversion);
  if (!(db.header->create() && db.getkey(false) && db.save()))
    throw FailEx();
}

// format a uuid into text
static secstring formatuuid(const secstring& uuid) {
  unsigned char uuid_array[16];
  char buf[16*3];
  memcpy(uuid_array, uuid.c_str(), sizeof(uuid_array));
  snprintf(buf, sizeof(buf),"%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
          uuid_array[0], uuid_array[1], uuid_array[2], uuid_array[3],
          uuid_array[4], uuid_array[5], uuid_array[6], uuid_array[7],
          uuid_array[8], uuid_array[9], uuid_array[10], uuid_array[11],
          uuid_array[12], uuid_array[13], uuid_array[14], uuid_array[15]);
  return buf;
}

static secstring xmlescape(const secstring& s) {
  // escape any non-xml characters and enclose the whole string in ""
  secstring out;
  out.reserve(s.length());

  out += '"';

  for (secstring::const_iterator i=s.begin(); i!=s.end(); ++i) {
    const unsigned char c = *i;
    if (c<' ' || c==0x7f) {
      // control character; emit in octal
      char buf[10];
      snprintf(buf,sizeof(buf),"\\%03o",c);
      out += buf;
      memset(buf,0,sizeof(buf));
    } else switch (c) {
      case '"': out += "&quot;"; break;
      case '&': out += "&amp;"; break;
      case '<': out += "&lt;"; break;
      case '>': out += "&gt;"; break;
      case '\\': out += "\\\\"; break;
      default: out += c;
    }
  }

  out += '"';
  return out;
}
  
void DB::exportdb() {
  matches_t matches;
  if (open()) {

    fprintf(outfile,"# passwordsafe version %s database\n", VERSION_NAME[version]);

    if (version == VERSION_1_7) fprintf(outfile, "%s\t%s\t%s\t%s\n", "name", "login", "passwd", "notes");
    else fprintf(outfile,"%s\t%s\t%s\t%s\t%s\t%s\n", "uuid", "group", "name", "login", "passwd", "notes");
    
    for (entries_t::const_iterator i=entries.begin(); i!=entries.end(); ++i) {
      const Entry& e = i->second;
      if (version == VERSION_1_7)
        fprintf(outfile,"%s\t%s\t%s\t%s\n", xmlescape(e.name).c_str(), xmlescape(!e.default_login?e.login:"[default]").c_str(), xmlescape(e.password).c_str(), xmlescape(e.notes).c_str());
      else
        fprintf(outfile,"%s\t%s\t%s\t%s\t%s\t%s\n", xmlescape(formatuuid(e.uuid)).c_str(), xmlescape(e.group).c_str(), xmlescape(e.name).c_str(), xmlescape(!e.default_login?e.login:"[default]").c_str(), xmlescape(e.password).c_str(), xmlescape(e.notes).c_str());
    }
  } else
    throw FailEx();
}

bool DB::add(const Entry& e) {
  secstring gn = e.groupname();
  if (entries.find(gn) != entries.end())
    return false;
  entries.insert(entries_t::value_type(gn,e));
  changed = true;
  if (arg_verbose > 0) printf("added %s\n", gn.c_str());
  return true;
}

bool DB::del(const Entry& e) {
  for (entries_t::iterator i = entries.begin(); i != entries.end(); ++i) {
    if (&i->second == &e) {
      if (arg_verbose > 0) printf("deleted %s\n", e.groupname().c_str()); // print this out before we delete it
      entries.erase(i);
      changed = true;
      return true;
    }
  }
  return false;
}

void DB::mergedb(DB& db2) {
  if (arg_verbose > 0) printf("merging %s into %s\n", db2.dbname, dbname);

  if (open() && db2.open(&passphrase)) { // try opening 2nd db using first's passphrase, since if we're merging the same db the passphrase is often identical
    int num_merged = 0, num_skipped = 0, num_dup = 0;

    for (entries_t::const_iterator i=db2.entries.begin(); i!=db2.entries.end(); ++i) {
      const Entry& e = i->second;
      bool done = false;
      for (entries_t::iterator j=entries.begin(); j!=entries.end(); ++j) {
        const Entry& f = j->second;

        if (e == f) {
          if (arg_verbose > 0) printf("skipping duplicate entry %s\n", e.groupname().c_str());
          num_dup++;
          done = true;
          break;
        }

        if ((e.uuid == f.uuid && !e.uuid.empty()) ||
            e.groupname() == f.groupname()) {
          // this is the same entry, but the contents are different
          secstring summary;
          f.diff(e,summary);
          while (!done) {
            switch (tolower(get1char("Entry "+e.groupname()+" differs ("+summary+"). Overwrite ? [y/N/d/?/q] ", 'n'))) {
              case 'y':
                del(f);
                add(e);
                num_merged++;
                done = true;
                break;
              case 'n':
                num_skipped++;
                done = true;
                break;
              case 'd': case '?':
                printf("%s", f.diff(e).c_str());
                break;
              case 'q':
                throw FailEx();
            }
          }
          break;
        }
      }
      if (!done) {
        add(e);
        num_merged++;
      }
    }
    
    // if the user specified the dbversion then consider that to be a change, so the use can mergedb a
    // database with itself in order to change version (yeah, it's kinda a hack, but it's also kinda unixy)
    if (arg_dbversion != version)
      changed = true;

    if (arg_verbose >= 0) 
      printf("Merged %d entries; skipped %d; %d duplicates.\n", num_merged, num_skipped, num_dup);
  } else
    throw FailEx();
}

void DB::passwd() {
  if (arg_verbose > 0) printf("rekeying %s\n", dbname);

  if (!(open()
        && header->create()
        && getkey(false, "Enter new passphrase", "Reenter new passphrase")))
    throw FailEx();
}

bool DB::getkey(bool test, const char* prompt1, const char* prompt2) {
  while (true) {
    const secstring pw = getpw(prompt1+std::string(" for ")+dbname_str+": ");
    if (!test) {
      const secstring pw2 = getpw(prompt2+std::string(" for ")+dbname_str+": ");
      if (pw != pw2) {
        printf("Passphrases do not match\n");
        continue;
      }
    }

    if (test) {
      // see if pw is correct
      if (testkey(pw)) {
        passphrase = pw;
        return true;
      } else {
        printf("Passphrase is incorrect\n");
        continue;
      }
    } else {
      // initialize hash correctly
      hashkey(pw, header->hash);
      passphrase = pw;
      changed = true; // since we've set/changed the passphrase, the db is changed
      return true;
    }
  }
}

bool DB::testkey(const secstring& pw) {
  unsigned char test_hash[sizeof(header->hash)];
  hashkey(pw,test_hash);
  if (memcmp(test_hash, header->hash, sizeof(header->hash)) == 0) {
    passphrase = pw;
    return true;
  } else {
    return false;
  }
}

void DB::hashkey(const secstring& pw, unsigned char test_hash[]) {
  // generate test hash from random and passphrase
  // I am mystified as to why Bruce uses these extra 2 zero bytes in the hashes
  SHA_CTX sha;
  SHA1_Init(&sha);
  SHA1_Update(&sha, header->random, sizeof(header->random));
  const static unsigned char zeros[2] = { 0,0 };
  SHA1_Update(&sha, zeros, 2);
  SHA1_Update(&sha, pw.data(), pw.length());

  unsigned char temp_key[SHA_DIGEST_LENGTH];
  SHA1_Final(temp_key, &sha);

  BF_KEY bf;
  BF_set_key(&bf, sizeof(temp_key), temp_key);

  Block block;
  block.read(header->random, sizeof(header->random));
  // to mimic passwordsafe I use BF_encrypt() directly, but that means I have to pretend that I am on a little-endian machine b/c passwordsafe assumes a i386
  for (int i=0; i<1000; ++i)
    BF_encrypt(block,&bf);

  unsigned char hash_data[8];
  block.write(hash_data);

  // Now comes a sad part: I have to hack to mimic the original passwordsafe which contains what I believe
  // is a bug. passwordsafe used its own blowfish and sha1 libraries, and its version of SHA1Final()
  // memset the sha context to 0's. However the passwordsafe code went ahead and performed a
  // SHA1Update on that zero'ed context. This of course did not crash anything, but it is not
  // a real sha hash b/c the initial state of a real sha1 is not all zeros. Also we end up only
  // hashing 8 bytes of stuff, so there are not 20 bytes of randomness in the result.
  // The good thing is we are hashing something which is already well hashed, so I doubt this
  // opened up any holes. But it does show that one should always step the program in a debugger
  // and watch what the variables are doing; sometimes it is eye opening!
  memset(&sha,0,sizeof(sha));
  SHA1_Update(&sha, hash_data, sizeof(hash_data));
  SHA1_Update(&sha, zeros, 2);
  SHA1_Final(test_hash, &sha);

  memset(&sha,0,sizeof(sha));
  memset(&bf,0,sizeof(bf));
  memset(temp_key,0,sizeof(temp_key));
}

bool DB::open(const secstring* pw_to_try) {
  if (opened)
    return true;

  FILE* file = fopen(dbname, "rb");
  if (!file) {
    fprintf(stderr,"Can't open %s: %s\n", dbname, strerror(errno));
    return false;
  }
  if (!header->read(file)) {
    fprintf(stderr,"Can't read %s: %s\n", dbname, pwsafe_strerror(errno));
    fclose(file);
    return false;
  }
 
  if ((pw_to_try && testkey(*pw_to_try)) || getkey(true)) {
    // load the rest of the file
    Context*const ctxt = new Context(*header, passphrase, version); // so context resides in secure memory
    try {
      errno = 0; // because successfull reads don't clear errno but it might be non-zero due to earlier failures (like backup file not existing)
      while (!feof(file)) {
        Entry e;
        if (e.read(file,*ctxt)) {
          // version 2 files are destinguished by a magic starting entry
          bool skip = false;
          if (version == VERSION_UNKNOWN) {
            version = (e.name == e.MAGIC_V2_NAME /* password save 2.05 does not check e.password, so I don't either && e.password == "2.0"*/) ? VERSION_2_0 : VERSION_1_7;
            if (arg_verbose > 0) printf("loading version %s database\n", VERSION_NAME[version]);
            if (version != VERSION_1_7) {
              v2_preferences = e.notes; // save preferences away so we can rewrite them when saving the file
              skip = true;
            }
          }
          if (!skip) entries.insert(entries_t::value_type(e.groupname(),e));
        } else {
          if (errno || !feof(file)) {
            delete ctxt;
            fprintf(stderr,"Can't read %s: %s\n", dbname, pwsafe_strerror(errno));
            fclose(file);
            return false;
          }
        }
      }
    } catch (...) {
      delete ctxt;
      throw;
    }
    delete ctxt;
  }

  if (fclose(file)) {
    fprintf(stderr, "Can't close %s: %s\n", dbname, strerror(errno));
    return false;
  }

  if (version == VERSION_UNKNOWN) {
    // assume empty files are v1.7, since a version 2.0 "empty" file would have contained the magic v2.0 entry
    version = VERSION_1_7;
  }
 
  if (arg_verbose > 1) printf("read in %zu entries\n", entries.size());

  opened = true;
  return true;
}

bool DB::backup() {
  char buf[1024];
  const std::string backupname_str = dbname_str+'~';
  const char*const backupname = backupname_str.c_str();

  if (arg_verbose > 0) printf("backing up %s to %s\n", dbname, backupname);

  FILE* f = fopen(dbname, "rb");
  if (!f) {
    fprintf(stderr,"Can't open %s: %s\n", dbname, strerror(errno));
    return false;
  }
  FILE* b = fopen(backupname, "wb");
  if (!b) {
    fprintf(stderr,"Can't open %s: %s\n", backupname, strerror(errno));
    fclose(f);
    return false;
  }
  while (true) {
    size_t rc = fread(buf,1,sizeof(buf),f);
    if (rc) {
      size_t rc2 = fwrite(buf,1,rc,b);
      if (rc != rc2) {
        fprintf(stderr,"Can't write %s: %s\n", backupname, strerror(errno));
        fclose(f);
        fclose(b);
        return false;
      }
    } else {
      if (ferror(f)) {
        fprintf(stderr,"Can't read %s: %s\n", dbname, strerror(errno));
        fclose(f);
        fclose(b);
        return false;
      } else
        break;
    }
  }
  fclose(f);
  if (fclose(b)) {
    fprintf(stderr,"Can't write %s: %s\n", backupname, strerror(errno));
    return false;
  }

  backedup = true;

  return true;
}

bool DB::restore() {
  if (!overwritten) {
    fprintf(stderr, "%s unchanged\n", dbname);
    return true;
  }

  const std::string backupname_str = dbname_str+'~';
  const char*const backupname = backupname_str.c_str();

  if (!backedup) {
    fprintf(stderr, "No backup of %s was created\nUNABLE TO RESTORE %s from %s\n", dbname, dbname, backupname);
    return false;
  }
  
  if (unlink(dbname) && errno != ENOENT) {
    fprintf(stderr, "unlink of %s failed: %s\nUNABLE TO RESTORE %s from %s\n", dbname, strerror(errno), dbname, backupname);
    return false;
  }
  if (rename(backupname, dbname)) {
    fprintf(stderr, "rename of %s to %s failed: %s\nUNABLE TO RESTORE %s from %s\n", backupname, dbname, strerror(errno), dbname, backupname);
    return false;
  }

  fprintf(stderr, "Successfully restored %s from backup\n", dbname);

  backedup = false; // the backup no longer exists
  overwritten = false; // and db file is no longer overwritten
  // leave changed alone, since changes, if they exist, are still in RAM

  return true;
}

bool DB::save() {
  Version saveversion = (arg_dbversion != VERSION_UNKNOWN ? arg_dbversion : version); // if the user specifies a dbversion then we convert
  
  if (arg_verbose > 0) printf("writing %s version %s\n", dbname, VERSION_NAME[saveversion]);

  // if this is a version change, then ask
  if (saveversion != version && 
      !getyn(std::string("Confirm overwriting version ")+VERSION_NAME[version]+" database "+dbname+" with a version "+VERSION_NAME[saveversion]+" database file ? "))
      return false;

  // we use a new salt and IV every time we save
  if (!header->resalt())
    return false;

  FILE* f = fopen(dbname, "wb");
  if (!f) {
    fprintf(stderr,"Can't open %s: %s\n", dbname, strerror(errno));
    return false;
  }

  overwritten = true; // we've now overwritten the db file and if the save() fails we need to restore from backup

  if (!header->write(f)) {
    fprintf(stderr,"Can't write %s: %s\n", dbname, pwsafe_strerror(errno));
    fclose(f);
    return false;
  }

  Context*const ctxt = new Context(*header, passphrase, saveversion);
  try {
    if (saveversion != VERSION_1_7) {
      // write the magic entry
      Entry e;
      e.name = Entry::MAGIC_V2_NAME;
      e.password = Entry::MAGIC_V2_PASSWORD;
      e.notes = v2_preferences;
      saveversion = VERSION_1_7; // temporarily true, since first entry is always written in v1.9 style
      e.write(f,*ctxt);
      saveversion = VERSION_2_0;
    }
    for (entries_t::const_iterator i=entries.begin(); i!=entries.end(); i++) {
      if (!i->second.write(f,*ctxt)) {
        delete ctxt;
        fprintf(stderr,"Can't write %s: %s\n", dbname, pwsafe_strerror(errno));
        fclose(f);
        return false;
      }
    }
  } catch (...) {
    delete ctxt;
    throw;
  }
  delete ctxt;

  if (fclose(f)) {
    fprintf(stderr,"Can't write/close %s: %s\n", dbname, strerror(errno));
    return false;
  }
 
  changed = false;

  return true;
}


bool DB::find(matches_t& matches, const char* regex_str /* might be NULL */) {
  if (arg_verbose > 0) printf("searching %s for %s\n", dbname, regex_str?regex_str:"<all>");

  regex_t regex;
  if (regex_str) {
    int rc = regcomp(&regex, regex_str, (arg_casesensative?0:REG_ICASE)|REG_NOSUB|REG_EXTENDED);
    if (rc) {
      size_t len = regerror(rc, &regex, NULL, 0);
      char*const msg = reinterpret_cast<char*>(malloc(len));
      if (msg) {
        regerror(rc, &regex, msg, len);
        fprintf(stderr,"%s\n", msg);
        free(msg);
      } else
        fprintf(stderr,"Out of memory\n");
      regfree(&regex);
      throw FailEx();
    }
  }

  for (entries_t::const_iterator i=entries.begin(); i!=entries.end(); ++i) {
    const Entry& e = i->second;
    if (!regex_str || !regexec(&regex, e.groupname().c_str(), 0,NULL, 0))
      matches.push_back(&e);
  }

  if (regex_str)
    regfree(&regex);

  return true;
}

const DB::Entry& DB::find1(const char* regex) {
  // first see if there is a perfect match for regex, treating regex as a literal string (and not a regex at all)
  {
    // first-first, try with a case sensative comparison even though they didn't ask for that
    for (entries_t::const_iterator i=entries.begin(); i!=entries.end(); ++i) {
      const Entry& e = i->second;
      if (strcmp(regex,e.groupname().c_str()) == 0) {
        return e;
      }
    }
  }

  // since that didn't work, try a case insensative comparison if that is a possibility
  if (!arg_casesensative) {
    matches_t matches;
    for (entries_t::const_iterator i=entries.begin(); i!=entries.end(); ++i) {
      const Entry& e = i->second;
      if (strcasecmp(regex,e.groupname().c_str()) == 0) {
        matches.push_back(&e);
      }
    }
    if (matches.size() == 1) // >1 might match b/c we are matching case insensative and they only differ by case
      return *matches.front();
  }

  matches_t matches;
  if (find(matches, regex)) {
    if (matches.size() == 0) {
      printf("No matching entries\n");
      throw FailEx();
    }
    if (matches.size() > 1) {
      printf("More than one matching entry: ");
      size_t count = 0;
      for (matches_t::const_iterator i=matches.begin(); i!=matches.end() && count < 3; ++i, ++count)
        printf("%s%s", (count?", ":""), (*i)->groupname().c_str());
      if (count != matches.size())
        printf(", ... (%zu more) ", matches.size()-3);
      printf(".\n");
      throw FailEx();
    }

    return *matches.front();
  } else
    throw FailEx();
}

void DB::list(const char* regex /* might be NULL */) {
  matches_t matches;
  if (open() && find(matches, regex)) {
    for (matches_t::const_iterator i=matches.begin(); i!=matches.end(); ++i) {
      const Entry& e = **i;
    
      if (arg_details) {
        // print out the name
        fprintf(outfile,"%s", e.groupname().c_str());
        
        // append the login if it exists
        if (!e.login.empty())
          fprintf(outfile,"  -  %s\n", e.login.c_str());
        else if (e.default_login)
          fprintf(outfile,"  -  [%s]\n", e.the_default_login.c_str());
        else
          fprintf(outfile,"\n");
 
        // print out the notes, prefixing each line with "> "
        emit_notes(e.notes);

        if (arg_verbose > 0) {
          if (!e.uuid.empty())
            // print out the UUID too
            fprintf(outfile, "%s\n", formatuuid(e.uuid).c_str());
          if (!e.extras.empty())
            fprintf(outfile, "and %zu unknown extra fields\n", e.extras.size());
        }
      } else
        // just print out the name
        fprintf(outfile,"%s\n", e.groupname().c_str());
    }
  }
}

void DB::emit(const char* regex, bool username, bool password, bool twice) {
  if (open()) {
    const Entry& e = find1(regex);

    if (!arg_echo && arg_details)
      // if we're not emit()ing to stdout, then print notes before sending login/password to X clipboard.
      // this way if the notes contain a URL, the user can cut/paste that too
      emit_notes(e.notes);

    if (username)
        for (int i = 0; i < (twice ? 2 : 1); i++)
            ::emit(e.groupname(), "username", e.default_login?e.the_default_login:e.login);
    if (password)
        for (int i = 0; i < (twice ? 2 : 1); i++)
            ::emit(e.groupname(), "password", e.password);
 
    if (arg_echo && arg_details)
      // if we didn't emit the notes above, do it now
      emit_notes(e.notes);
  }
}

void DB::add(const char* name /* might be NULL */) {
  if (arg_verbose > 0) printf("adding %s%sto %s\n", (name?name:""),(name?" ":""), dbname);
  if (open()) {
    Entry e;
    if (name) {
      if (version != VERSION_1_7) {
        // if the argument contains a single '.' that isn't the first or last char, use that to split group and name
        const char* dot = strchr(name,'.');
        if (dot && dot != name && dot[1] != '\0' && strrchr(name,'.') == dot) {
          e.name.assign(dot+1);
          e.group.assign(name, dot-name);
        } else
          e.name = name;
      } else
        e.name = name;
    }

    while (true) {
      if (e.name.empty())
        e.name = gettxt("name: ");
      if (version != VERSION_1_7 && e.group.empty())
        e.group = gettxt("group [<none>]: ");
 
      if (entries.find(e.groupname()) != entries.end()) {
        fprintf(stderr,"%s already exists\n", e.groupname().c_str());
        if (name)
          throw FailEx();
        e.name.erase();
        e.group.erase();
      } else if (!e.name.empty())
        break;
    }

    e.login = gettxt("username: ");
    if (e.login.empty())
      e.default_login = getyn("use default username ("+e.the_default_login+") ? [n] ", false);

    e.password = enter_password("password [return for random]: ", "password again: ");
 
    e.notes = gettxt("notes: ");
 
    entries.insert(entries_t::value_type(e.groupname(),e));
    changed = true;
  } else
    throw FailEx();
} 

void DB::edit(const char* regex) {
  if (open()) {
    const Entry& e_orig = find1(regex);
    Entry e = e_orig; // make a local copy to edit

    while (true) {
      e.name = gettxt("name: ["+e_orig.name+"] ", e_orig.name);
      if (version != VERSION_1_7)
        e.group = gettxt("group: ["+e_orig.group+"] ", e_orig.group);
      if ((e.name == e_orig.name && e.group == e_orig.group) || 
          entries.find(e.groupname()) == entries.end()) // e.name cannot be empty b/c if the user entered an empty string they got the old name
        break;
      printf("%s already exists\n", e.groupname().c_str());
    }

 
    if (e.default_login)
      e.default_login = getyn("keep default username ("+e_orig.the_default_login+") ? [y]", true);
    if (!e.default_login) {
      e.login = gettxt("username: ["+e_orig.login+"] ", e_orig.login);
      if (e.login.empty() && !e_orig.default_login) // no point in asking if they just disabled default login
        e.default_login = getyn("use default username ("+e_orig.the_default_login+") ? [n]", false);
    }


    while (true) {
      if (getyn("change password ? [n] ", false)) {
        secstring new_pw = enter_password("new password: [return for random]", "new password again: ");
        if (new_pw.empty() && !e.password.empty()) {
          if (!getyn("Confirm changing to an empty password ? [n] "))
            continue;
        }
        e.password = new_pw;
      }
      break;
    }

    e.notes = gettxt("notes: [<keep same>] ", e_orig.notes);

    if (e_orig != e) {
      typedef std::vector<std::string> changes_t;
      changes_t changes;
      
      if (e_orig.group != e.group) changes.push_back("group");
      if (e_orig.name != e.name) changes.push_back("name");
      if (e_orig.default_login != e.default_login || 
          (!e_orig.default_login && !e.default_login && e_orig.login != e.login))
        changes.push_back("login");
      if (e_orig.password != e.password)
        changes.push_back("password");
      if (e_orig.notes != e.notes)
        changes.push_back("notes");

      std::string prompt = "Confirm changing ";
      for (changes_t::const_iterator i=changes.begin(); i!=changes.end(); ++i) {
        if (i != changes.begin()) prompt += ", ";
        prompt += *i;
      }
      prompt += " ? [y]";
      if (getyn(prompt, true)) {
        entries.erase(entries.find(e_orig.groupname()));
        entries.insert(entries_t::value_type(e.groupname(),e));
        changed = true;
      } else
        printf("Changes abandoned\n");
    }
    else
      printf("No change\n");
  }
}
 

void DB::del(const char* name) {
  if (arg_verbose > 0) printf("deleting %s from %s\n", name, dbname);
  if (open()) {
    entries_t::iterator i = entries.find(name);
    if (i == entries.end()) {
      fprintf(stderr,"%s not found\n", name);
      throw FailEx();
    }

    entries.erase(i);
    changed = true;
  }
}


// ----- DB::Header class ----------------------------------------------

DB::Header::Header() {
  zero();
}

DB::Header::~Header() {
  zero();
}

void DB::Header::zero() {
  memset(random,0,sizeof(random));
  memset(hash,0,sizeof(hash));
  memset(salt,0,sizeof(salt));
  memset(iv,0,sizeof(iv));
}

bool DB::Header::create() {
  if (!RAND_bytes(random, sizeof(random)) ||
      !RAND_bytes(salt, sizeof(salt)) ||
      !RAND_bytes(iv, sizeof(iv))) {
    fprintf(stderr,"Can't get random number: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return false;
  }
  memset(hash,0,sizeof(hash));
  return true;
}

bool DB::Header::resalt() {
  // new salt, and new iv too while we are at it
  if (!RAND_bytes(salt, sizeof(salt)) ||
      !RAND_bytes(iv, sizeof(iv))) {
    fprintf(stderr,"Can't get random number: %s\n", ERR_error_string(ERR_get_error(), NULL));
    return false;
  }
  return true;
}

bool DB::Header::read(FILE* f) {
  if (fread(random, 1,sizeof(random), f) != sizeof(random) ||
      fread(hash, 1,sizeof(hash), f) != sizeof(hash) ||
      fread(salt, 1,sizeof(salt), f) != sizeof(salt) ||
      fread(iv, 1,sizeof(iv), f) != sizeof(iv)) {
    return false;
  }
  return true;
}

bool DB::Header::write(FILE* f) const {
  if (fwrite(random, 1,sizeof(random), f) != sizeof(random) ||
      fwrite(hash, 1,sizeof(hash), f) != sizeof(hash) ||
      fwrite(salt, 1,sizeof(salt), f) != sizeof(salt) ||
      fwrite(iv, 1,sizeof(iv), f) != sizeof(iv)) {
    return false;
  }
  return true;
}

// ----- DB::Context class --------------------------------------------

DB::Context::Context(const Header& h, const secstring& pw, const Version& v) :
  version(v)
{
  cbc.read(h.iv,sizeof(h.iv));
  SHA_CTX sha;
  SHA1_Init(&sha);
  SHA1_Update(&sha, pw.data(), pw.length());
  SHA1_Update(&sha, h.salt, sizeof(h.salt));
  unsigned char key[SHA_DIGEST_LENGTH];
  SHA1_Final(key, &sha);
  BF_set_key(&bf, sizeof(key), key);
  memset(&sha,0,sizeof(sha));
  memset(&key,0,sizeof(key));
}

DB::Context::~Context() {
  memset(&bf,0,sizeof(bf));
}

// ----- DB::Entry class ----------------------------------------------

const char*const DB::Entry::SPLIT_STR = "  \xAD  ";
const char*const DB::Entry::MAGIC_V2_NAME = " !!!Version 2 File Format!!! "
                                                   "Please upgrade to PasswordSafe 2.0"
                                                   " or later";
const char*const DB::Entry::MAGIC_V2_PASSWORD = "2.0";

secstring DB::Entry::the_default_login;

void DB::Entry::Init() {
  const char* dl = getenv("PWSAFE_DEFAULT_USER");
  if (!dl) {
    dl = getenv("USER");
    if (!dl) {
      dl = getenv("LOGNAME");
      if (!dl) {
        // fine, we'll go get LOGNAME from the pwdatabase
        const struct passwd*const pw = getpwuid(getuid());
        if (pw) {
          dl = pw->pw_name;
        } else {
          // no USER, no LOGNAME, no /etc/passwd entry for this UID; they're on their own now
          dl = "";
        }
      }
    }
  }
  the_default_login = dl;
}

DB::Entry::Entry() : default_login(false) {
  // ok; no-op
}

bool DB::Entry::operator!=(const Entry& e) const {
  return uuid != e.uuid ||
    group != e.group ||
    name != e.name ||
    default_login != e.default_login ||
    (!default_login && !e.default_login && login != e.login) ||
    password != e.password ||
    notes != e.notes;
}

int DB::Entry::diff(const Entry& e, secstring& summary) const {
  int n = 0;
  if (uuid != e.uuid) {
    summary += "uuid, ";
    n++;
  }
  if (group != e.group) {
    summary += "group, ";
    n++;
  }
  if (name != e.name) {
    summary += "name, ";
    n++;
  }
  if (default_login != e.default_login) {
    summary += "login, ";
    n++;
  }
  if (!default_login && !e.default_login && login != e.login) {
    summary += "login, ";
    n++;
  }
  if (password != e.password) {
    summary += "password, ";
    n++;
  }
  if (notes != e.notes) {
    summary += "notes, ";
    n++;
  }
  if (n > 0) {
    // strip off trailing ", "
    summary = summary.substr(0, summary.length()-2);
  }
  return n;
}

secstring DB::Entry::diff(const Entry& e) const {
  secstring s;
  if (uuid != e.uuid) 
    s += "UUID -- " + uuid + "\n"
         "UUID ++ " + e.uuid + "\n";
  if (group != e.group)
    s += "GROUP -- \"" + group + "\"\n"
         "GROUP ++ \"" + e.group + "\"\n";
  if (name != e.name)
    s += "NAME -- \"" + name + "\"\n"
         "NAME ++ \"" + e.name + "\"\n";
  if (default_login != e.default_login) {
    s += "DEFAULT LOGIN -- ";
    s += (default_login ? "yes" : "no");
    s += "\n"
         "DEFAULT LOGIN ++ ";
    s += (e.default_login ? "yes" : "no");
    s += "\n";
  }
  if (!default_login && !e.default_login && login != e.login)
    s += "LOGIN -- \"" + login + "\"\n"
         "LOGIN ++ \"" + e.login + "\"\n";
  if (password != e.password)
    s += "PASSWORD -- <not shown>\n"
         "PASSWORD ++ <not shown>\n";
  if (notes != e.notes)
    s += "NOTES -- \"" + notes + "\"\n"
         "NOTES ++ \"" + e.notes + "\"\n";
  return s;
}

secstring DB::Entry::groupname() const {
  // prefix the name with the group, if it exists
  return group.empty() ? name : group+'.'+name;
}

bool DB::Entry::read(FILE* f, DB::Context& c) {
  bool rc = true;
  uint8_t type;
  if (c.version > VERSION_1_7) {
    int max_fields = 255;
    do {
      secstring s;
      rc &= read(f,c,type,s);
      if (rc) {
        switch (type) {
          case UUID: uuid=s; break;
          case GROUP: group=s; break;
          case TITLE: name=s; break;
          case USER: login=s; break;
          case NOTES: notes=s; break;
          case PASSWORD: password=s; break;
          case END: break;
          default:
            if (arg_verbose > 0) printf("reading field of unknown type %u\n", static_cast<int>(type));
            extras.push_back(extras_t::value_type(type,s));
        }
      }
    } while (rc && type != END && --max_fields);
    if (!max_fields) {
      fprintf(stderr, "Too many fields in database entry. Is database corrupt?\n");
      return false;
    }
  } else {
    // read a version 1.7 entry
    secstring name_login;
    rc = read(f,c,type,name_login) &&
      read(f,c,type,password) && 
      read(f,c,type,notes);
    if (rc) {
      // split name_login if it contains the magic split char
      secstring::size_type p = name_login.find(SPLIT_CHAR);
      if (p != name_login.npos && p>0) {
        name = name_login.substr(0,p);
        login = name_login.substr(p+1,name_login.npos);
      } else {
        p = name_login.find(DEFAULT_USER_CHAR);
        if (p != name_login.npos && p>0) {
          // this entry uses the default login. this is not part of the database; instead it is part of the configuration, or in our case, $USER
          name = name_login.substr(0,p);
          login = the_default_login;
          default_login = true;
        } else {
          // no magic split chars; assume this is a very old database that contains no login field
          name = name_login;
        }
      }
      // and trim any extra whitespace from the end of name and the begining of login
      p = name.find_last_not_of(' ');
      if (p != name.npos)
        name = name.substr(0,p+1);
      else
        name.erase(); // nothing left of name
      p = login.find_first_not_of(' ');
      if (p != login.npos)
        login = login.substr(p,login.npos);
      else
        login.erase(); // nothing left of login
    }
  }

  if (arg_verbose > 2 && rc)
    printf("read in entry %s\n", groupname().c_str());

  return rc;
}

bool DB::Entry::write(FILE* f, DB::Context& c) const {
  if (arg_verbose > 2)
    printf("writing entry %s\n", name.c_str());

  // remove 'false' and create a entry named zzz to deliberate cause failure to write
  if (false && name == "zzz") {
    fprintf(stderr, "Deliberately failing to save entry zzz\n");
    return false;
  }

  if (c.version != VERSION_1_7) {
    secstring save_uuid = uuid;
    if (uuid.empty()) {
      // we must have read in a v1.7 file; create a uuid on the fly
      // NOTE: instead of creating a per-rfc UUID which includes hardware-identificators like your 1st NIC's MAC address, 
      // I make it completely random. I like this better, and given the size of the UUID collisions won't be a problem.
      unsigned char buf[16];
      if (!RAND_bytes(buf,sizeof(buf))) {
        fprintf(stderr, "Can't get random data: %s\n", ERR_error_string(ERR_get_error(), NULL));
        throw FailEx();
      }
      save_uuid.assign(reinterpret_cast<const char*>(buf),sizeof(buf));
      memset(buf,0,sizeof(buf));
    }
    return write(f,c,UUID,save_uuid) &&
      write(f,c,GROUP,group) &&
      write(f,c,TITLE,name) &&
      write(f,c,USER,login) &&
      write(f,c,PASSWORD,password) &&
      write(f,c,NOTES,notes) &&
      write(f,c,extras) &&
      write(f,c,END,"");
  } else {
    // here I follow the same wierd login encoding as passwordsafe 1.9, including inserting extra spaces as well as the SPLIT_CHAR between name and login
    // it doesnt look like anything depends on those spaces, but...
    secstring name_login;
    if (!group.empty())
      name_login = group + '.'; // passwordsafe 2.0 prepends the v2.0 group when writing a v1.7 file, so I do it too
    if (default_login) // this this first so that if the_default_login is "" we still get it right (so here I don't follow passwordsafe)
      name_login += name + DEFAULT_USER_CHAR;
    else if (login.empty())
      name_login += name;
    else
      name_login += name + SPLIT_STR + login;

    return write(f,c,NAME,name_login) &&
      write(f,c,PASSWORD,password) &&
      write(f,c,NOTES,notes);
  }
}

bool DB::Entry::read(FILE* f, DB::Context& c, uint8_t& type, secstring& str) {
  str.erase();
  
  Block block;
  if (!block.read(f))
    return false;
  
  Block copy = block;
  BF_decrypt(block, &c.bf);
  block ^= c.cbc;
  c.cbc = copy;

  const int32_t len = block.getInt32();
  type = block.getType();

  block.zero();
  copy.zero();
  
  if (len < 0) {
    // set errno to something smart
    errno = PWSAFE_ERR_INVALID_DB;
    return false;
  }

  // make sure len isn't completely nuts (we could also compare with remaining file length...)
  if (len > 64*1024) {
    errno = PWSAFE_ERR_INVALID_DB;
    return false;
  }

  int numblocks = (len+8-1)/8;
  if (numblocks == 0)
    numblocks = 1;

  str.resize(len);

  for (int i=0; i<numblocks; i++) {
    if (!block.read(f))
      return false;
    copy = block;
    BF_decrypt(block, &c.bf);
    block ^= c.cbc;
    unsigned char data[8];
    block.write(data);
    for (int j=0; j<8 && i*8+j<len; j++)
      str[i*8+j] = data[j];
    c.cbc = copy;
  }

  return true;
}

bool DB::Entry::write(FILE* f, DB::Context& c, const extras_t& extras) {
  bool rc = true;
  for (extras_t::const_iterator i=extras.begin(); rc && i!=extras.end(); ++i)
    rc &= write(f,c,i->first,i->second);
  return rc;
}

bool DB::Entry::write(FILE* f, DB::Context& c, uint8_t type, const secstring& str) {
  const unsigned char*const data = reinterpret_cast<const unsigned char*>(str.data());
  
  int numblocks = (str.length()+8-1)/8;
  if (numblocks == 0)
    numblocks = 1; // always have one block, even if it is all zero's

  { // write the string's length
    Block block;
    block.putInt32AndType(str.length(), (c.version != VERSION_1_7 ? type : 0));
    block ^= c.cbc;
    BF_encrypt(block, &c.bf);
    c.cbc = block;
    if (!block.write(f))
      return false;
  }

  // then blocks of data; the last one padded with zero's
  for (int i=0; i<numblocks; i++) {
    Block block;
    block.read(data+i*8, std::min(8, int(str.length())-i*8));
    block ^= c.cbc;
    BF_encrypt(block, &c.bf);
    c.cbc = block;
    if (!block.write(f))
      return false;
  }
  
  return true;
}


// ---- secalloc class ---------------------------------------

secalloc::Pool* secalloc::pools = NULL;
size_t secalloc::pagesize = 0;
const size_t secalloc::alignsize = std::max(sizeof(double),
#if HAVE_LONG_LONG
                                            sizeof(long long)
#else
                                            sizeof(long)
#endif
                                           );

secalloc::Pool::Pool(size_t n) : next(0), top(0), bottom(0), level(0) {
  char*const z = 0;
  const size_t pagesize = secalloc::pagesize;
  char*const p = reinterpret_cast<char*>(malloc(pagesize+n+pagesize)); // make sure we get something that is page-aligned
  if (!p) {
    fprintf(stderr, "Out of memory\n");
    throw FailEx();
  }
  bottom = p;
  level = z + ((bottom-z+pagesize-1) & ~(pagesize-1)); // round bottom up to a page boundary
  top = z + ((bottom-z+pagesize+n+pagesize) & ~(pagesize-1)); // round top down to a page boundary

  // mark level..top as non-swapabble
  int rc = mlock(level,top-level);
  // Redhat FC3 returns ENOMEM if not root, not EPERM, so dont bother checking for EPERM error from mlock(); treat any error to mean 'try mlock() against as SUID user'
  if (rc && (saved_uid != geteuid() || saved_gid != getegid())) {
    // try again as root (or whoever saved_uid really is)
    int dont_care; // gcc+glibc is a PITA about ignoring certain failures. I don't care if these fail. I try the mlock and if it fails, it fails.
    if (saved_uid != geteuid()) 
      dont_care = seteuid(saved_uid);
    if (saved_gid != getegid())
      dont_care = setegid(saved_gid);
    rc = mlock(level,top-level);
    dont_care = setegid(getgid());
    dont_care = seteuid(getuid());
    (void)dont_care;
  }
  if (rc) {
    static bool reported = false;
    if (!reported) {
      if (arg_verbose >= 0)
        fprintf(stderr, "WARNING: %s unable to use secure ram (need to be setuid root)\n", program_name);
      reported = true;
    }
  }
}

secalloc::Pool::~Pool() {
  char*const z = 0;
  const size_t pagesize = secalloc::pagesize;
  memset(bottom, 0, top-bottom); // clear it once more, just in case everything wasn't properly deallocate()ed
  char*const l = z + ((bottom-z+pagesize-1) & ~(pagesize-1)); // recalculate original value we passed to mlock()
  munlock(l, top-l); // might fail; that's ok if it does
  free(bottom);
}

secalloc::secalloc() {
  init();
}

void secalloc::init() {
  if (pagesize == 0) { // initialize pagesize the first time we are called
    pagesize = getpagesize();
  
    if (pagesize == (size_t)-1 || pagesize == 0) {
      const char errstr[] = "Error: can't compute kernel MMU page size\n";
      int dont_care = write(STDERR_FILENO, errstr, sizeof(errstr)); // at the point when init() is called, stderr is not necessarily setup
      (void)dont_care; // I don't care if this write() failed. This is severe failure path code anyway.
      throw FailEx();
    }
  }
}

void secalloc::cleanup() {
  while (pools) {
    Pool* p = pools;
    pools = p->next;
    delete p;
  }
}

void* secalloc::allocate(size_t n) {
  if (!pools || static_cast<size_t>(pools->top - pools->level) < n) {
    // need a new pool
    Pool* p = new (std::nothrow) Pool(std::max(n, static_cast<size_t>(16*pagesize)));
    if (!p) {
      fprintf(stderr, "Error: %s out of memory\n", program_name);
      throw FailEx();
    }
    p->next = pools;
    pools = p;
  }

  void* p = pools->level;
  pools->level += (n+alignsize-1) & ~(alignsize-1);
  return p;
}

void secalloc::deallocate(void* p, size_t n) {
  memset(p,0,n);
}

void* secalloc::reallocate(void* p, size_t old_n, size_t new_n) {
  void* new_p = allocate(new_n);
  memcpy(new_p, p, std::min(old_n, new_n));
  deallocate(p, old_n);
  return new_p;
}

// --- cheap getopt_long() substitute ----------------------------------------------------------

#ifndef HAS_GETOPT_LONG
// a cheap substitute for getopt_long() that doesn't support optional arguments, nor does it reorder argv[] to put non-options last
static int getopt_long(int argc, char*const argv[], const char* short_opts, const long_option* lopts, int* flag) {
  if (optind >= argc)
    // nothing left at all
    return -1;
  
  const char*const p = argv[optind];
  if (p[0] != '-' || p[1] != '-')
    // not a long option. since we don't reorder argv[] we let getopt() have a crack at it
    return getopt(argc, argv, short_opts);

  while (lopts && lopts->name) {
    if (strcmp(lopts->name, p+2) == 0) {
      // we have a match
      optind++;
      if (lopts->has_arg == required_argument) {
        if (optind >= argc) {
          fprintf(stderr, "option `%s' requires an argument\n", p);
          return ':';
        }
        optarg = argv[optind++];
      }

      if (lopts->flag) {
        *lopts->flag = lopts->val;
        return 0;
      }
      else
        return lopts->val;
    } else
      lopts++;
  }
  // not an option that matches
  fprintf(stderr, "unrecognized option `%s'\n", p);
  return '?';
}
#endif // HAS_GETOPT_LONG

