/* 
   pwsafe - commandline tool compatible with Counterpane's Passwordsafe

   Copyright (C) 2004 Nicolas S. Dade

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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <getopt.h>
#include <errno.h>
#include <pwd.h>
#include <regex.h>

#include <string>
#include <map>
#include <algorithm>

#include "system.h"

#include <termios.h>

// fix a few things that system.h setup and that readline.h isn't going to like
#undef ISDIGIT
#undef IN_CTYPE_DOMAIN

#ifdef READLINE_H_NEEDS_EXTERN_C
extern "C" {
#endif
#include <readline/readline.h>
#ifdef READLINE_H_NEEDS_EXTERN_C
} // terminate extern "C"
#endif

#include <curses.h>

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

// The name the program was run with, stripped of any leading path
const char *program_name;

// Option flags and variables
const char* arg_dbname = NULL;
const char* arg_name = NULL;
enum OP { OP_NOP, OP_CREATEDB, OP_PASSWD, OP_LIST, OP_ADD, OP_DELETE };
OP arg_op = OP_NOP;
bool arg_echo = false;
const char* arg_output = NULL;
FILE* outfile = NULL; // will be arg_output() or stdout
bool arg_username = false;
bool arg_password = false;
bool arg_details = false;
int arg_verbose = 0;
#ifndef X_DISPLAY_MISSING
bool arg_xclip = false;
const char* arg_display = NULL;
const char* arg_selection = "both"; // by default copy to primary X selection and clipboard
static Display* xdisplay = NULL;
#endif

static struct option const long_options[] =
{
  // commands
  {"createdb", no_argument, 0, 'C'},
  {"passwd", no_argument, 0, 'P'},
  {"list", no_argument, 0, 'L'},
  {"add", no_argument, 0, 'a'},
  {"delete", no_argument, 0, 'D'},
  // options
  {"file", required_argument, 0, 'f'},
  // options controlling what is outputted
  {"long", no_argument, 0, 'l'},
  {"username", no_argument, 0, 'u'},
  {"password", no_argument, 0, 'p'},
  // options controlling where output goes
  {"echo", no_argument, 0, 'e'},
  {"output", required_argument, 0, 'o'},
#ifndef X_DISPLAY_MISSING
  {"xclip", no_argument, 0, 'x'},
  {"display", required_argument, 0,'d'},
  {"selection", required_argument, 0,'s'},
#endif
  // standard stuff
  {"verbose", no_argument, 0, 'v'},
  {"help", no_argument, 0, 'h'},
  {"version", no_argument, 0, 'V'},
  {NULL, 0, NULL, 0}
};

static void usage(bool fail);
static int parse(int argc, char **argv);
static const char* pwsafe_strerror(int err); // decodes errno's as well as our negative error codes
#define PWSAFE_ERR_INVALID_DB -1

static bool getyn(const std::string& prompt, int def_val=-1);

typedef std::string secstring; // for now; later we can modify the storage so it is not swapped out, and overwritten when freed

struct FailEx {}; // thrown to unwind, cleanup and cause main to return 1
  
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

  int32_t getInt32() const;
  void putInt32(int32_t);

  Block& operator ^=(const Block&);

  void read(const unsigned char*, int len);
  void write(unsigned char[8]) const;

  bool read(FILE*);
  bool write(FILE*) const;
};
  


class DB {
private:
  // the file header
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
  };
  Header* header; // so header can be in secure memory

  // the crypto context (exists only when read/writing the database)
  struct Context {
    Block cbc;
    BF_KEY bf;

    Context(const Header&, const secstring& pw);
    ~Context();
  };

  struct Entry {
  private:
    // the name+login fields are saved as one string in the file for historical reasons (login was added after 1.0), seperated by magic characters we hope you won't use in a name
    const static char SPLIT_CHAR = '\xAD';
    const static char*const SPLIT_STR;// = "  \xAD  ";
    const static char DEFAULT_USER_CHAR = '\xA0';
 
    static bool read(FILE*, Context&, secstring&);
    static bool write(FILE*, Context&, const secstring&);

  public:
    static secstring the_default_login;
    secstring name;
    secstring login;
    bool default_login;
    secstring password;
    secstring notes;

    static void Init(); // computes the_default_login
    Entry();
    bool read(FILE*, Context&);
    bool write(FILE*, Context&) const;
  };
  typedef std::map<secstring, Entry> entries_t;
  entries_t entries;

  secstring passphrase;
  bool opened; // true after open() has succeeded
  bool changed; // unsaved changes have been made
  bool backedup; // true after backup() has succeeded
  bool overwritten; // true once we start overwriting dbname

  bool getkey(bool test, const char* prompt1="Enter passphrase", const char* prompt2="Reenter passphrase"); // ask for password
  bool open(); // call getkey(), read file into entries map
public:
  const std::string dbname_str;
  const char*const dbname;

  static void Init();
  DB(const char* dbname);
  ~DB();

  static void createdb(const char* dbname);
  void passwd();
  void list(const char* regex);
  void add(const char* name);
  void del(const char* name);

  bool is_changed() const { return changed; }

  bool backup(); // create ~ file
  bool save(); // write out db file (please backup() first if appropriate)
  bool restore(); // copy ~ file back to original (only if an earlier call to backup() suceeded)
};


int main (int argc, char **argv) {
  try {
    program_name = strrchr(argv[0], '/');
    if (!program_name)
      program_name = argv[0];
    else
      program_name++;

    // be nice and paranoid
    umask(0077);

    // init some arguments
    {
      const char* home = getenv("HOME");
      if (home) {
        const char* defname = "/.pwsafe.dat";
        char* dbname = reinterpret_cast<char*>(malloc(strlen(home)+strlen(defname)+1));
        strcpy(dbname, home);
        strcat(dbname, defname);
        arg_dbname = dbname;
      }

#ifndef X_DISPLAY_MISSING
      if (isatty(STDOUT_FILENO) && (arg_display = XDisplayName(NULL)))
        arg_xclip = true;
      else
#endif
        arg_echo = true;
    }

    int idx = parse(argc, argv);
 
    if (arg_op == OP_NOP)
      // assume --list
      arg_op = OP_LIST;
    
    if (idx != argc) {
      if ((arg_op == OP_LIST || arg_op == OP_ADD || arg_op == OP_DELETE) && idx+1 == argc) {
        arg_name = argv[idx];
      } else {
        fprintf(stderr, "%s - Too many arguments\n", program_name);
        usage(true);
      }
    }

    if (!arg_dbname) {
      // $HOME wasn't set and -f wasn't used; we have no idea what we should be opening
      fprintf(stderr, "$HOME wasn't set; --file must be used\n");
      throw FailEx();
    }

    if (!arg_name && (arg_op == OP_DELETE)) {
      fprintf(stderr, "--delete must take an argument\n");
      throw FailEx();
    }

#ifndef X_DISPLAY_MISSING
    if (arg_xclip && !XDisplayName(arg_display)) {
      fprintf(stderr, "$DISPLAY isn't set; use --display\n");
      throw FailEx();
    }
#endif

    // if arg_output was given, use that
    if (arg_output) {
      outfile = fopen(arg_output,"w");
    } else if (!isatty(STDOUT_FILENO) && isatty(STDERR_FILENO)) {
      // if stdout is not a tty but stderr is, use stderr to interact with the user, but still write the output to stdout
      dup2(STDOUT_FILENO,3);
      dup2(STDERR_FILENO,STDOUT_FILENO);
      outfile = fdopen(3,"w");
    } else {
      // use stdout
      outfile = fdopen(dup(STDOUT_FILENO),"w");
    }
    if (!outfile) {
      fprintf(stderr, "Can't open %s: %s\n", arg_output, strerror(errno));
      throw FailEx();
    }

#ifndef X_DISPLAY_MISSING
    if (arg_verbose && (arg_password || arg_username) && (arg_echo || arg_xclip))
      printf("Going to copy %s to %s\n", arg_password&&arg_username?"login and password":arg_password?"password":"login", arg_xclip?"X selection":"stdout");
#else
    if (arg_verbose && (arg_password || arg_username) && (arg_echo))
      printf("Going to copy %s to %s\n", arg_password&&arg_username?"login and password":arg_password?"password":"login", "stdout");
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
    case OP_PASSWD:
    case OP_LIST:
    case OP_ADD:
    case OP_DELETE:
      {
        DB db(arg_dbname);
        try {
          switch (arg_op) {
          case OP_PASSWD:
            db.passwd();
            break;
          case OP_LIST:
            db.list(arg_name);
            break;
          case OP_ADD:
            db.add(arg_name);
            if (!arg_name) {
              // let them add more than one without having to reenter the passphrase
              while (getyn("Add another? [n] ", false))
                db.add(NULL);
            }
            break;
          case OP_DELETE:
            db.del(arg_name);
            break;
          }

          // backup and save if changes have occured
          if (db.is_changed()) {
            if (arg_verbose) printf("Saving changes to %s\n", db.dbname);
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

#ifndef X_DISPLAY_MISSING
    if (xdisplay)
      XCloseDisplay(xdisplay);
#endif
    if (outfile)
      if (fclose(outfile)) {
        fprintf(stderr, "Can't write/close output: %s", strerror(errno));
        outfile = NULL;
        throw FailEx();
      }

    return 0;
    
  } catch (const FailEx&) {
#ifndef X_DISPLAY_MISSING
    if (xdisplay)
      XCloseDisplay(xdisplay);
#endif
    if (outfile)
      fclose(outfile);

    return 1;
  }
}

// Set all the option flags according to the switches specified.
// Return the index of the first non-option argument.
static int parse(int argc, char **argv) {
  int c;

  while ((c = getopt_long (argc, argv,
          "l"  // long listing
          "a" // add
          "f:"  // file
          "e"   // echo
          "o:"  // output
          "u"   // user
          "p"   // password
#ifndef X_DISPLAY_MISSING
          "x"   // xclip
          "d:"  // display
          "s:"  // x selection
#endif
          "v"   // verbose
          "h"   // help
          "V",	// version
          long_options, (int *) 0)) != EOF)
  {
    switch (c) {
      case 'C':
        if (arg_op == OP_NOP)
          arg_op = OP_CREATEDB;
        else
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
        if (arg_op == OP_NOP) {
          arg_op = OP_ADD;
        } else
          usage(true);
        break;
      case 'D':
        if (arg_op == OP_NOP) {
          arg_op = OP_DELETE;
        } else
          usage(true);
        break;
      case 'f':
        arg_dbname = optarg;
        break;
      case 'l':
        if (arg_op == OP_NOP || arg_op == OP_LIST) {
          arg_op = OP_LIST;
          arg_details = true;
        } else
          usage(true);
        break;
      case 'o':
        arg_output = optarg;
        // fall through into 'e' since -o implies -e
      case 'e':
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
#ifndef X_DISPLAY_MISSING
      case 'd':
        arg_display = optarg;
        arg_xclip = true; arg_echo = false; // -d implies -x
        break;
      case 's':
        arg_selection = optarg; // we can't parse it until we open X
        // -s implies -x, so no 'break'
      case 'x':
        arg_xclip = true; arg_echo = false;
        break;
#endif
      case 'v':
        arg_verbose++;
        break;
      case 'V':
        printf("pwsafe %s\n", VERSION);
        exit(0);
      case 'h':
        usage(false);
        exit(0);
      case ':':
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
        "  -f, --file=DATABASE_FILE   specify the database file (default is ~/.pwsafe.dat)\n"
        "  -l                         long listing\n"
        "  -u, --username             emit username of listed account(s)\n"
        "  -p, --password             emit password of listed account(s)\n"
        "  -e, --echo                 force echoing of entry to stdout\n"
        "  -o, --output=FILE          redirect output to file (implies -e)\n"
#ifndef X_DISPLAY_MISSING
        "  -x, --xclip                force copying of entry to X selection\n"
        "  -d, --display=XDISPLAY     override $DISPLAY (implies -x)\n"
        "  -s, --selection={Primary,Secondary,Clipboard,Both} select the X selection effected (implies -x)\n"
#endif
        "  -v, --verbose              print more information (can be repeated)\n"
        "  -h, --help                 display this help and exit\n"
        "  -V, --version              output version information and exit\n"
        "Commands:\n"
        "  --createdb                 create an empty database\n"
        "  --passwd                   change database passphrase\n"
        "  [--list] [REGEX]           list all [matching] entries\n"
        "  -a, --add [NAME]           add an entry\n"
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
      

// get a password from the user
static secstring getpw(const std::string& prompt) {
  // turn off echo
  struct termios tio;
  tcgetattr(STDIN_FILENO, &tio);
  tio.c_lflag &= ~(ECHO);
  tcsetattr(STDIN_FILENO, TCSAFLUSH, &tio); // FLUSH so they don't get into the habit of typing ahead their passphrase
  char* x = readline(prompt.c_str());
  // restore echo
  tio.c_lflag |= (ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &tio);
  // echo a linefeed since the user's <Enter> was not echoed
  printf("\n");
  // see what readline returned
  if (x) {
    secstring xx(x);
    memset(x,0,strlen(x));
    free(x);
    return xx;
  } else {
    // EOF/^d; abort
    throw FailEx();
  }
}

static secstring gettxt(const std::string& prompt) {
  char* x = readline(prompt.c_str());
  if (x) {
    secstring xx(x);
    memset(x,0,strlen(x));
    free(x);
    return xx;
  } else {
    // EOF/^d; abort
    throw FailEx();
  }
}

static bool getyn(const std::string& prompt, int def_val) {
  struct termios tio;
  tcgetattr(STDIN_FILENO, &tio);
  tio.c_lflag &= ~(ICANON);
  tcsetattr(STDIN_FILENO, TCSADRAIN, &tio);
  tio.c_lflag |= (ICANON); // get ready to turn ICANON back on

  while (true) {
    printf("%s",prompt.c_str());
    fflush(stdout);
    char x;
    ssize_t rc = read(STDIN_FILENO,&x,1);

    if (rc == 1) {
      switch (x) {
      case 'Y':
      case 'y':
        printf("\n");
        tcsetattr(STDIN_FILENO, TCSANOW, &tio);
        return true;
      case 'N':
      case 'n':
        printf("\n");
        tcsetattr(STDIN_FILENO, TCSANOW, &tio);
        return false;
      case '\r':
        printf("\n");
        // fall through
      case '\n':
        if (def_val >= 0) {
          tcsetattr(STDIN_FILENO, TCSANOW, &tio);
          return !!def_val;
        }
        // else there is no default and the user must answer
      }
      // if we get this far the user didn't answer, and we loop and reprompt them
      printf("\n");
    }
    else {
      tcsetattr(STDIN_FILENO, TCSANOW, &tio);
      throw FailEx();
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

void Block::putInt32(int32_t x) {
  block[0] = x;
  block[1] = 0;
}

int32_t Block::getInt32() const {
  return block[0]; // because we are always byte-ordered correctly, we can just do this
}

void Block::read(const unsigned char* data, int len) {
  if (len < sizeof(block))
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

DB::DB(const char* n) : 
  dbname_str(n), dbname(dbname_str.c_str()), opened(false), changed(false), backedup(false), overwritten(false)
{
  header = new Header();
}

DB::~DB() {
  delete header;
}

void DB::createdb(const char* dbname) {
  if (arg_verbose) printf("creating %s\n", dbname);
  
  // be sure not to overwrite an existing file
  struct stat s;
  if (!stat(dbname, &s)) {
    fprintf(stderr, "%s already exists\n", dbname);
    throw FailEx();
  }

  DB db(dbname);
  if (!(db.header->create() && db.getkey(false) && db.save()))
    throw FailEx();
}

void DB::passwd() {
  if (arg_verbose) printf("rekeying %s\n", dbname);

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

    unsigned char test_hash[sizeof(header->hash)];
    { // generate test hash from random and passphrase
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

    if (test) {
      // see if pw is correct
      if (memcmp(test_hash, header->hash, sizeof(header->hash)) != 0) {
        printf("Passphrase is incorrect\n");
        continue;
      } else {
        passphrase = pw;
        return true;
      }
    } else {
      // initialize hash correctly
      memcpy(header->hash, test_hash, sizeof(header->hash));
      passphrase = pw;
      changed = true; // since we've set/changed the passphrase, the db is changed
      return true;
    }
  }
}

bool DB::open() {
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
 
  if (getkey(true)) {
    // load the rest of the file
    
    Context ctxt(*header, passphrase);

    errno = 0; // because successfull reads don't clear errno but it might be non-zero due to earlier failures (like backup file not existing)
    while (!feof(file)) {
      Entry e;
      if (e.read(file,ctxt)) {
        entries.insert(entries_t::value_type(e.name,e));
      } else {
        if (errno || !feof(file)) {
          fprintf(stderr,"Can't read %s: %s\n", dbname, pwsafe_strerror(errno));
          fclose(file);
          return false;
        }
      }
    }
  }

  if (fclose(file)) {
    fprintf(stderr, "Can't close %s: %s\n", dbname, strerror(errno));
    return false;
  }
 
  if (arg_verbose > 1) printf("Read in %u entries\n", entries.size());

  opened = true;
  return true;
}

bool DB::backup() {
  char buf[1024];
  const std::string backupname_str = dbname_str+'~';
  const char*const backupname = backupname_str.c_str();

  if (arg_verbose) printf("backing up %s to %s\n", dbname, backupname);

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
  if (arg_verbose) printf("writing %s\n", dbname);

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

  Context ctxt(*header, passphrase);

  for (entries_t::const_iterator i=entries.begin(); i!=entries.end(); i++) {
    if (!i->second.write(f,ctxt)) {
      fprintf(stderr,"Can't write %s: %s\n", dbname, pwsafe_strerror(errno));
      fclose(f);
      return false;
    }
  }

  if (fclose(f)) {
    fprintf(stderr,"Can't write/close %s: %s\n", dbname, strerror(errno));
    return false;
  }
 
  changed = false;

  return true;
}


static void emit(const secstring& name, const char*const what, const secstring& txt) {
  if (arg_echo) {
    if (isatty(fileno(outfile)))
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

    static const Atom CLIPBOARD = XA_CLIPBOARD(xdisplay); // optimize by fetching this one only once

    Atom xsel1 = 0, xsel2 = 0;
    int num_sel = 1;
    switch (tolower(arg_selection[0])) {
      case 'b': case '0': xsel1 = XA_PRIMARY; xsel2 = CLIPBOARD; num_sel = 2; break;
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
    while (xsel1 || xsel2) {
      XEvent xev;
      XNextEvent(xdisplay, &xev);
 
      if (xev.type == PropertyNotify) {
        if (!timestamp && xev.xproperty.window == xwin && xev.xproperty.state == PropertyNewValue && xev.xproperty.atom == XA_WM_COMMAND) {
          timestamp = xev.xproperty.time; // save away the timestamp; that's all we really wanted
          XSetSelectionOwner(xdisplay, xsel1, xwin, timestamp);
          if (xsel2)
            XSetSelectionOwner(xdisplay, xsel2, xwin, timestamp);
          if (xsel2 && XGetSelectionOwner(xdisplay, xsel2) != xwin) {
            fprintf(stderr, "Unable to own X selection %s\n", stxt2);
            xsel2 = 0;
            num_sel--;
          }
          if (XGetSelectionOwner(xdisplay, xsel1) != xwin) {
            fprintf(stderr, "Unable to own X selection %s\n", stxt1);
            xsel1 = xsel2;
            if (stxt1) XFree(stxt1);
            stxt1 = stxt2;
            xsel2 = 0; stxt2 = NULL;
            num_sel--;
          }

          // let the user know
          if (arg_verbose>1) {
            if (xsel1 && xsel2)
              printf("X selections %s and %s contain %s for %s\n", stxt1, stxt2, what, name.c_str());
            else if (xsel1)
              printf("X selection %s contains %s for %s\n", stxt1, what, name.c_str());
          } else {
            if (xsel1 && xsel2)
              printf("You are ready to paste the %s for %s from %s and %s\n", what, name.c_str(), stxt1, stxt2);
            else if (xsel1)
              printf("You are ready to paste the %s for %s from %s\n", what, name.c_str(), stxt1);
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
            const Atom targets[] = { XA_TARGETS(xdisplay), XA_TIMESTAMP(xdisplay), XA_TEXT(xdisplay), XA_STRING };
            XChangeProperty(xdisplay, xev.xselectionrequest.requestor, prop, XA_TARGETS(xdisplay), 32, PropModeReplace, reinterpret_cast<const unsigned char*>(&targets), sizeof(targets)/sizeof(targets[0]));
          }
          else if (xev.xselectionrequest.target == XA_TIMESTAMP(xdisplay)) {
            XChangeProperty(xdisplay, xev.xselectionrequest.requestor, prop, XA_TIMESTAMP(xdisplay), 32, PropModeReplace, reinterpret_cast<const unsigned char*>(&timestamp), 1);
          }
          else if (xev.xselectionrequest.target == XA_TEXT(xdisplay) ||
              xev.xselectionrequest.target == XA_STRING) {
            if (/*arg_verbose &&*/ xev.xselectionrequest.requestor != prev_requestor && xev.xselectionrequest.requestor != prevprev_requestor) { // programs like KDE's Klipper re-request every second, so it isn't very useful to print out multiple times
              // be very verbose about who is asking for the selection---it could catch a clipboard sniffer
              const char*const selection = xev.xselectionrequest.selection == xsel1 ? stxt1 : stxt2; // we know xselectionrequest.selection is xsel1 or xsel2 already, so no need to be more paranoid

              // walk up the tree looking for a client window
              Window w = xev.xselectionrequest.requestor;
              while (true) {
                XTextProperty tp = { value: NULL };
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
              XTextProperty nm = { value: NULL };
              if ((XGetWMName(xdisplay, w, &nm) && nm.encoding == XA_STRING && nm.format == 8 && nm.value) ||
                  (((nm.value?(XFree(nm.value),nm.value=NULL):0), XGetTextProperty(xdisplay, w, &nm, XA_WM_COMMAND)) && nm.encoding == XA_STRING && nm.format == 8 && nm.value)) // try getting WM_COMMAND if we can't get WM_NAME
                requestor = reinterpret_cast<const char*>(nm.value);
  
              const char* host = "<unknown>";
              XTextProperty cm = { value: NULL };
              if (XGetWMClientMachine(xdisplay, w, &cm) && cm.encoding == XA_STRING && cm.format == 8)
                host = reinterpret_cast<const char*>(cm.value);
 
              printf("Sending %s for %s to %s@%s via %s\n", what, name.c_str(), requestor, host, selection);

              if (nm.value) XFree(nm.value);
              if (cm.value) XFree(cm.value);
            }
            XChangeProperty(xdisplay, xev.xselectionrequest.requestor, prop, XA_STRING, 8, PropModeReplace, reinterpret_cast<const unsigned char*>(txt.c_str()), txt.length());
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
        bool done = true;
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

    if (arg_verbose>1) printf("X selection%s cleared\n",(num_sel>1?"s":""));

    if (stxt1) XFree(stxt1);
    if (stxt2) XFree(stxt2);
  }
#endif
}

void DB::list(const char* regex_str /* might be NULL */) {
  if (arg_verbose) printf("searching %s for %s\n", dbname, regex_str?regex_str:"<all>");

  regex_t regex;
  if (regex_str) {
    int rc = regcomp(&regex, regex_str, REG_ICASE|REG_NOSUB|REG_EXTENDED);
    if (rc) {
      size_t len = regerror(rc, &regex, NULL, 0);
      char* msg = new char[len];
      regerror(rc, &regex, msg, len);
      fprintf(stderr,"%s\n", msg);
      delete [] msg;
      regfree(&regex);
      throw FailEx();
    }
  }

  if (open()) {
    for (entries_t::const_iterator i=entries.begin(); i!=entries.end(); ++i) {
      const Entry& e = i->second;
      if (!regex_str || !regexec(&regex, e.name.c_str(), 0,NULL, 0)) {
        if (arg_details) {
          // print out the name
          fprintf(outfile,"%s", e.name.c_str());
          
          // append the login if it exists
          if (!e.login.empty())
            fprintf(outfile,"  -  %s\n", e.login.c_str());
          else if (e.default_login)
            fprintf(outfile,"  -  [%s]\n", e.the_default_login.c_str());
          else
            fprintf(outfile,"\n");
        } else if (!(arg_username || arg_password))
          // just print out the name
          fprintf(outfile,"%s\n", e.name.c_str());
        // else we are going to emit something, so don't print anything
 
        if (arg_username)
          emit(e.name, "username", e.default_login?e.the_default_login:e.login);
        if (arg_password)
          emit(e.name, "password", e.password);

        if (arg_details) {
          // print out the notes, prefixing each line with "> "
          if (!e.notes.empty()) {
            const char* p = e.notes.c_str();
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
      }
    }
  }

  if (regex_str)
    regfree(&regex);
}

void DB::add(const char* name /* might be NULL */) {
  if (arg_verbose) printf("adding %s%sto %s\n", (name?name:""),(name?" ":""), dbname);
  if (open()) {
    Entry e;
    if (name)
      e.name = name;
    while (e.name.empty()) {
      e.name = gettxt("name: ");

      if (entries.find(e.name) != entries.end()) {
        fprintf(stderr,"%s already exists\n", e.name.c_str());
        if (name)
          throw FailEx();
        else
          e.name.erase();
      }
    }

    e.login = gettxt("username: ");
    if (e.login.empty())
      e.default_login = getyn("use default login ("+e.the_default_login+") ? [n] ", false);
    e.password = getpw("password: ");
    e.notes = gettxt("notes: ");
 
    entries.insert(entries_t::value_type(e.name,e));
    changed = true;
  }
} 

void DB::del(const char* name) {
  if (arg_verbose) printf("deleting %s from %s\n", name, dbname);
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

DB::Context::Context(const Header& h, const secstring& pw) {
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

bool DB::Entry::read(FILE* f, DB::Context& c) {
  secstring name_login;
  bool rc = read(f,c,name_login) &&
    read(f,c,password) && 
    read(f,c,notes);
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
    // and trim any extra whitespace from name and login
    p = name.find_last_not_of(' ');
    if (p != name.npos)
      name = name.substr(0,p+1);
    p = login.find_first_not_of(' ');
    if (p != login.npos)
      login = login.substr(p,login.npos);

    if (arg_verbose > 2)
      printf("Read in entry %s\n", name.c_str());
  }
  return rc;
}

bool DB::Entry::write(FILE* f, DB::Context& c) const {
  if (arg_verbose > 2)
    printf("Writing entry %s\n", name.c_str());

  // remove 'false' and create a entry named zzz to deliberate cause failure to write
  if (false && name == "zzz") {
    fprintf(stderr, "Deliberately failing to save entry zzz\n");
    return false;
  }

  // here I follow the same wierd login as passwordsafe, including inserting extra spaces as well as the SPLIT_CHAR between name and login
  // it doesnt look like anything depends on those spaces, but...
  secstring name_login;
  if (default_login) // this this first so that if the_default_login is "" we still get it right (so here I don't follow passwordsafe)
    name_login = name + DEFAULT_USER_CHAR;
  else if (login.empty())
    name_login = name;
  else
    name_login = name + SPLIT_STR + login;

  return write(f,c,name_login) &&
    write(f,c,password) &&
    write(f,c,notes);
}

bool DB::Entry::read(FILE* f, DB::Context& c, secstring& str) {
  str.erase();
  
  Block block;
  if (!block.read(f))
    return false;
  
  Block copy = block;
  BF_decrypt(block, &c.bf);
  block ^= c.cbc;
  c.cbc = copy;

  const int32_t len = block.getInt32();

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

bool DB::Entry::write(FILE* f, DB::Context& c, const secstring& str) {
  const unsigned char*const data = reinterpret_cast<const unsigned char*>(str.data());
  
  int numblocks = (str.length()+8-1)/8;
  if (numblocks == 0)
    numblocks = 1; // always have one block, even if it is all zero's

  { // write the string's length
    Block block;
    block.putInt32(str.length());
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


