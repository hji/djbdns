#include <sys/types.h>
#include <regex.h>

typedef struct regex_list_elem *regex_eptr;
typedef struct regex_list_elem {
  regex_t* re;
  regex_eptr next_regex;
} regex_elem;

typedef struct proxy_rule *prule_ptr;
typedef struct proxy_rule {
  char *rdata;
  unsigned char ipl[4],ipu[4];
  char type[2],type2[2],rlength[2],ttl[4];
  int match_ttl;
  int nxdomain;
  regex_eptr first_regex;
  prule_ptr next;
} prule;

typedef struct res_rec {
  char class[2],type[2],rlength[2],ttl[4];
  unsigned char names[5];
  char *other;
} rrec;

extern int build_rulebase(const char *);
extern void convert(char *,unsigned int,char *);
