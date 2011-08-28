#include <stdio.h>
#include <string.h>
#include "alloc.h"
#include "byte.h"
#include "dns.h"
#include "dns_proxy.h"
#include "response.h"

static prule_ptr first;

#define N 200
static char names[N][256];
static unsigned int name_num,rec_num,first_ns;
static unsigned int qdcount,ancount,nscount,arcount;
static rrec rrecords[50];

// rule tokenizing function
// expects 6 fields separated by ';', fields themselves must not contain ';'
int strtoken(char *s,char **ip,char **name1,char **type1,char **name2,char **type2,char **ttl) {
  int delims = 5,ld,ld2;
  int i,j = 0,k,len = 0,p = 0;

  for (k=0;*(s+k) != '\0';++k) if (*(s+k) == ';') {ld2 = ld; ld = k;}
  for (k=0;*(s+k) != ';' && *(s+k) != '\0';++k);
  if (*(s+k) == '\0') return -2;
  len = k+1; *ip = alloc(len);

  for (i=0;*(s+i) != '\0';++i) {
     if ( *(s+i) == ';') {
       switch (delims) {
        case 0: return -1;
        case 1: *(*type2+j) = '\0'; 
                for (k=0;*(s+i+1+k) != ';' && *(s+i+1+k) != '\0';++k);
                if (*(s+i+1+k) == ';') return -2;
                len = k+1; *ttl = alloc(len);
                break;
        case 2: if (i == ld2) {
                *(*name2+j) = '\0';
                for (k=0;*(s+i+1+k) != ';' && *(s+i+1+k) != '\0';++k);
                if (*(s+i+1+k) == '\0') return -2;
                len = k+1; *type2 = alloc(len);
                } else { *(*name2+j) = *(s+i); ++j; p = 1; }
                break;
        case 3: *(*type1+j) = '\0'; 
                *name2 = alloc(ld2-i);
                break;
        case 4: *(*name1+j) = '\0';   
                for (k=0;*(s+i+1+k) != ';' && *(s+i+1+k) != '\0';++k);
                if (*(s+i+1+k) == '\0') return -2;
                len = k+1; *type1 = alloc(len);
                break;
        case 5: *(*ip+j) = '\0'; 
                for (k=0;*(s+i+1+k) != ';' && *(s+i+1+k) != '\0';++k);
                if (*(s+i+1+k) == '\0') return -2;
                len = k+1; *name1 = alloc(len);
                break;
       }
       if (!p) {j = 0; --delims;} else p = 0;
     }
     else {
       switch (delims) {
        case 0: *(*ttl+j) = *(s+i); break;
        case 1: *(*type2+j) = *(s+i); break;
        case 2: *(*name2+j) = *(s+i); break;
        case 3: *(*type1+j) = *(s+i); break;
        case 4: *(*name1+j) = *(s+i); break;
        case 5: *(*ip+j) = *(s+i); break;
       }
       ++j;
     }
  }
  if (delims != 0) return -1;
  *(*ttl+j) = '\0';
  return 0;
}

int str_to_ip(char *s,unsigned char ip_low[4],unsigned char ip_up[4]) {
  int i,j = 0,low = 1;
  int ip_l[4],ip_u[4];

  ip_l[0] = -1; ip_l[1] = -1; ip_l[2] = -1; ip_l[3] = -1;
  ip_u[0] = -1; ip_u[1] = -1; ip_u[2] = -1; ip_u[3] = -1;

  for (i=0;s[i] != '\0';++i)
     if (s[i] == '.') {
       if (i > 0 && s[i-1] == '-') ip_u[j] = 255;
       low = 1;
       if (j < 3) ++j; else return 0;
     }
     else  if (s[i] == '-') low = 0;
           else if (s[i] >= '0' && s[i] <= '9')
                   if (low) { if (ip_l[j] < 0) ip_l[j] = 0;
                              if (ip_l[j] < 25 || ip_l[j] == 25 && s[i] < '6') 
                                ip_l[j] = ip_l[j]*10 + (int) (s[i]-'0'); 
                              else return 0;
                            }
                   else { if (ip_u[j] < 0) ip_l[j] = 0;
                          if (ip_u[j] < 25 || ip_u[j] == 25 && s[i] < '6') 
                                ip_u[j] = ip_u[j]*10 + (int) (s[i]-'0');
                          else return 0;
                        }
           else return 0;

  if (j < 3) return 0;

  for (j=0;j < 4;++j) { 
       if (ip_l[j] == -1) { ip_l[j] = 0; ip_u[j] = 255; }
       else if (ip_u[j] == -1) ip_u[j] = ip_l[j];
       if (ip_l[j] > ip_u[j]) return 0;
  }     
  for (j=0;j < 4;++j) { ip_up[j] = ip_u[j]; ip_low[j] = ip_l[j]; }
  return 1;
}

int match_ip(char ip[4],unsigned char ip_low[4],unsigned char ip_up[4]) {
  unsigned char ip_seg;
  int i;
  for (i = 0;i < 4;++i) { 
    ip_seg = ip[i];
    if (ip_low[i]>ip_seg || ip_up[i]<ip_seg) return 0; 
  }
  return 1;
}

int str_to_type(char *s,char *type) {
  if (s[0] == '\0') { type[0] = '\1'; type[1] = '\1'; }
  else if (strcmp(s,"A") == 0) { type[0] = '\0'; type[1] = '\1'; }
  else if (strcmp(s,"NS") == 0) { type[0] = '\0'; type[1] = '\2'; }
  else if (strcmp(s,"CNAME") == 0) { type[0] = '\0'; type[1] = '\5'; }
  else if (strcmp(s,"SOA") == 0) { type[0] = '\0'; type[1] = '\6'; }
  else if (strcmp(s,"PTR") == 0) { type[0] = '\0'; type[1] = '\14'; }
  else if (strcmp(s,"MX") == 0) { type[0] = '\0'; type[1] = '\17'; }
  else if (strcmp(s,"TXT") == 0) { type[0] = '\0'; type[1] = '\20'; }
  else { return 0; }
  return 1;
}

int str_to_ttl(char *s,char ttl[4]) {
  unsigned long ttl_l;
  int i;

  for (i=0;s[i] != '\0';++i);
  for (;s[i] < '0' && i>=0;--i) s[i] = '\0';
  ttl_l = 0;
  for (i=0;s[i] != '\0';++i) {
     if (s[i] < '0' || s[i] > '9') return 0;
     if ((ttl_l > 429496729) || ((ttl_l == 429496729) && (s[i] > '5'))) return 0;
     ttl_l = 10 * ttl_l + (int) (s[i] - '0');
  }
  for (i=0;i < 4;++i) { ttl[3-i] = (char) ttl_l % 256;
                        ttl_l = ttl_l / 256; 
                      }
  return 1;
}

int str_to_name(char *s,char **s2) {
  int i,j=0,l;
  if (s[0] == '\0') { (*s2) = alloc(1); (*s2)[0] = '\0'; return 1; }
  for (i=0;s[i]!='\0';++i);
  l = i;
  if (l>255) return 0;
  (*s2) = alloc(l+1);
  (*s2)[i+1] = s[i]; --i;
  for (;i>=0;--i)
  if (s[i] != '.') { (*s2)[i+1] = s[i]; ++j; }
  else { if (j>63) return 0; (*s2)[i+1] = j; j = 0; }
  (*s2)[0] = j; if (j>63) return 0;
  return l+2;
}

int str_to_rdata(char *s,char type[2],char **rd,char rlength[2]) {
  unsigned int val,i,j,k,len;
  char *s2,*s3,*s4;
  unsigned char ipl[4],ipu[4],rlen[2];
  if (byte_equal(type,2,DNS_T_A)) {
         *rd = alloc(4);
         if (str_to_ip(s,ipl,ipu) == 0) return 0;
         for (i=0;i < 4;++i) if (ipl[i] != ipu[i]) return 0; else (*rd)[i] = ipl[i];
         rlen[0] = 0; rlen[1] = 4;
  }
  if (byte_equal(type,2,DNS_T_NS) || 
      byte_equal(type,2,DNS_T_CNAME) ||
      byte_equal(type,2,DNS_T_PTR)) {
         len = str_to_name(s,rd);
         if (len == 0) return 0;
         rlen[0] = (char)(len / 256); rlen[1] = (char)(len % 256);
  }
  if (byte_equal(type,2,DNS_T_SOA)) {
         for (i=0;s[i] != ':' && s[i] != '\0';++i); j = i; if (s[i]=='\0') return 0;
         ++i;
         s2 = alloc(j+1);
         for (;s[i] != ':' && s[i] != '\0';++i); len = i; if (s[i]=='\0') return 0;
         s3 = alloc(len-j);
         for (i=0;s[i] != ':';++i) s2[i] = s[i];
         s2[i] = '\0';
         ++i;
         for (;s[i] != ':';++i) s3[i-j-1] = s[i];
         ++i;
         s3[i-j-1] = '\0';
         len = str_to_name(s2,rd);
         if (len == 0) return 0;
         k = str_to_name(s3,&s4);
         if (k == 0) return 0;
         len += k;
         len += 20;
         rlen[0] = (char)(len / 256); rlen[1] = (char)(len % 256);
         alloc_free(s2);
         s2 = alloc(len);
         for (j=0;(*rd)[j] != '\0';++j) s2[j] = (*rd)[j];
         s2[j] = (*rd)[j];
         k = ++j;
         for (j=0;s4[j] != '\0';++j) s2[j+k] = s4[j];
         s2[j+k] = s4[j];
         alloc_free(s4);
         alloc_free(*rd);
         j = j+k+1;
         val = 0;
         for (;s[i]>='0' && s[i] <= '9';++i) 
           if (val < 429496729 || (val == 429496729 && s[i] < '6')) val = 10 * val + (unsigned int)(s[i]-'0');
           else return 0;
         if (s[i] != ':') return 0;
         for (k=0;k<4;++k) { s2[j+3-k] = (char)(val % 256); val = val / 256; }
         j += 4; ++i;
         val = 0;
         for (;s[i]>='0' && s[i] <= '9';++i) 
           if (val < 429496729 || (val == 429496729 && s[i] < '6')) val = 10 * val + (unsigned int)(s[i]-'0');
           else return 0;
         if (s[i] != ':') return 0;
         for (k=0;k<4;++k) { s2[j+3-k] = (char)(val % 256); val = val / 256; }
         j += 4; ++i;
         val = 0;
         for (;s[i]>='0' && s[i] <= '9';++i) 
           if (val < 429496729 || (val == 429496729 && s[i] < '6')) val = 10 * val + (unsigned int)(s[i]-'0');
           else return 0;
         if (s[i] != ':') return 0;
         for (k=0;k<4;++k) { s2[j+3-k] = (char)(val % 256); val = val / 256; }
         j += 4; ++i;
         val = 0;
         for (;s[i]>='0' && s[i] <= '9';++i) 
           if (val < 429496729 || (val == 429496729 && s[i] < '6')) val = 10 * val + (unsigned int)(s[i]-'0');
           else return 0;
         if (s[i] != ':') return 0;
         for (k=0;k<4;++k) { s2[j+3-k] = (char)(val % 256); val = val / 256; }
         j += 4; ++i;
         val = 0;
         for (;s[i]>='0' && s[i] <= '9';++i) 
           if (val < 429496729 || (val == 429496729 && s[i] < '6')) val = 10 * val + (unsigned int)(s[i]-'0');
           else return 0;
         if (s[i] != '\0') return 0;
         for (k=0;k<4;++k) { s2[j+3-k] = (char)(val % 256); val = val / 256; }
         (*rd) = s2;
  }
  if (byte_equal(type,2,DNS_T_MX)) {
         val = 0;
         for (i=0;s[i]>='0' && s[i]<='9';++i) 
             if (val < 6553 || (val == 6553 && s[i] < '6')) val = 10 * val + (unsigned int)(s[i] - '0');
             else return 0;
         if (s[i++] != ':') return 0;
         for (len = 0;s[len+i] != '\0';++len);
         s2 = alloc(len+1);
         for (len = 0;s[len+i] != '\0';++len) s2[len] = s[len+i];
         s2[len] = '\0';
         len = str_to_name(s2,rd);
         if (len == 0) return 0;
         alloc_free(s2);
         s2 = alloc(len+2);
         for (i=0;i<len;++i) s2[i+2] = (*rd)[i];
         s2[0] = (char)(val / 256); s2[1] = (char)(val % 256);
         alloc_free(*rd);
         (*rd) = s2;
         rlen[0] = (char)((len+2) / 256); rlen[1] = (char)((len+2) % 256);
  }
  if (byte_equal(type,2,DNS_T_TXT)) {
         for (i=0;s[i] != '\0';++i);
         len = i;
         if (len>255) return 0;
         *rd = alloc(len+1);
         for (i=0;s[i] != '\0';++i) (*rd)[i+1] = s[i];
         (*rd)[0] = (char) len;
         rlen[0] = (len+1) / 256; rlen[1] = (len+1) % 256;
  }

  rlength[0] = rlen[0]; rlength[1] = rlen[1];
  return 1;
}

regex_eptr make_regex_list(char *s) {
  char s2[200],s3[200];
  int i,j = 0,in_paren = 0,k;
  regex_eptr first_regex_elem,firstsub = NULL; //,actsub;
  first_regex_elem = (regex_eptr)calloc(1,sizeof(regex_elem));
  for (i=0;s[i] != '\0';++i) {
    /* XXX --- sub regexps not supported yet ---
      if (s[i]=='(' && !in_paren) { return NULL;
                                in_paren = 1; k = 0; 
                              }
      else if (s[i] == ')' && in_paren) { 
          in_paren = 0; s3[k] = '\0';
          s2[j++] = '.'; s2[j++] = '*';
          if (firstsub == NULL) { 
               firstsub = (regex_eptr)calloc(1,sizeof(regex_elem));
               actsub = firstsub;
          }
          else {
               actsub->next_regex = (regex_eptr)calloc(1,sizeof(regex_elem));
               actsub = actsub->next_regex;
          }
          actsub->next_regex = NULL;
          actsub->re = (regex_t*)calloc(1,sizeof(regex_t));
          //if (regcomp(actsub->re,,REG_EXTENDED | REG_ICASE) != 0) return NULL;
      }
      else*/ if (!in_paren) s2[j++] = s[i];
      else if (in_paren) s3[k++] = s[i];
  }
  s2[j] = '\0';
  first_regex_elem->re = (regex_t*)calloc(1,sizeof(regex_t));
  if(regcomp(first_regex_elem->re,s2,REG_EXTENDED | REG_ICASE) != 0) return NULL;
  first_regex_elem->next_regex = firstsub;
  return first_regex_elem;
}

prule_ptr make_rule(char *s) {
  prule_ptr newr = (prule_ptr)calloc(1,sizeof(prule));
  char *n1,*n2,*t1,*t2,*ttl,*ip;

  if (strtoken(s,&ip,&n1,&t1,&n2,&t2,&ttl) != 0) return NULL;
  if ((n2[0] != '\0' && strcmp(n2,"NXDOMAIN") != 0 && t2[0] == '\0') || 
      (n2[0] == '\0' && t2[0] != '\0')) return NULL;
  newr->first_regex = make_regex_list(n1);
  if (newr->first_regex == NULL) return NULL;
  if (!str_to_ip(ip,newr->ipl,newr->ipu)) return NULL;
  if (!str_to_type(t1,newr->type)) return NULL;
  if (strcmp(n2,"NXDOMAIN") == 0) newr->nxdomain = 1;
  else {
    newr -> nxdomain = 0;
    if (!str_to_type(t2,newr->type2)) return NULL;
    if (str_to_rdata(n2,newr->type2,&(newr->rdata),newr->rlength) == 0) return NULL;
  }

  if (ttl[0] == '\0') newr->match_ttl = 0;
  else { 
    newr->match_ttl = 1;
    str_to_ttl(ttl,newr->ttl);
  }

  newr->next = NULL;
  alloc_free(n1);
  alloc_free(n2);
  alloc_free(ip);
  alloc_free(t1);
  alloc_free(t2);
  alloc_free(ttl);
  return newr;
}

unsigned int get_name_at_pos(char *r,char *name,unsigned int base) {
  unsigned char len = r[base];
  unsigned int posmod = 0;
  int i,j = 0;
  if (r[base] == '\0') { name[j] = '\0'; posmod = 1; return posmod; }
  while (r[base] != '\0') {
    if (len > 63) { base = (unsigned int)(256 * ((unsigned char)r[base]-192) + (unsigned char)r[base+1]);
                    if (posmod == 0) posmod = j+2; 
                  }
    else { for (i = 0;i < len;++i) name[j++] = r[base+i+1];
           name[j++] = '.';
           base += len+1;
         }
    len = r[base];
  }
  if (posmod == 0) posmod = j+1;
  name[j-1] = '\0';
  return posmod;
}

void get_resource_rec_at_pos(char *rptr,unsigned int *pos,rrec *rr) {
  
  unsigned int i = *pos,j;
  rr->names[0] = 1;

  i += get_name_at_pos(rptr,names[name_num],i);  
  rr->names[1] = name_num;
  ++name_num;
  rr->type[0] = rptr[i++]; rr->type[1] = rptr[i++];
  rr->class[0] = rptr[i++]; rr->class[1] = rptr[i++];
  rr->ttl[0] = rptr[i++]; rr->ttl[1] = rptr[i++];
  rr->ttl[2] = rptr[i++]; rr->ttl[3] = rptr[i++];
  rr->rlength[0] = rptr[i++]; rr->rlength[1] = rptr[i++];
  
  if (byte_equal(rr->type,2,DNS_T_A)) {
         rr->other = alloc(4);
         for (j=0;j<4;++j) *(rr->other+j) = rptr[i++];
  }
  if (byte_equal(rr->type,2,DNS_T_NS) ||
      byte_equal(rr->type,2,DNS_T_CNAME) ||
      byte_equal(rr->type,2,DNS_T_PTR)) {
         i += get_name_at_pos(rptr,names[name_num],i);
         ++(rr->names[0]);
         rr->names[rr->names[0]] = name_num;
         ++name_num;
  }
  if (byte_equal(rr->type,2,DNS_T_SOA)) {
         i += get_name_at_pos(rptr,names[name_num],i);
         ++(rr->names[0]);
         rr->names[rr->names[0]] = name_num;
         ++name_num;
         i += get_name_at_pos(rptr,names[name_num],i);
         ++(rr->names[0]);
         rr->names[rr->names[0]] = name_num;
         ++name_num;
         rr->other = alloc(20);
         for (j=0;j<20;++j) *(rr->other+j) = rptr[i++];
  }
  if (byte_equal(rr->type,2,DNS_T_MX)) {
         rr->other = alloc(2);
         for (j=0;j<2;++j) *(rr->other+j) = rptr[i++];
         i += get_name_at_pos(rptr,names[name_num],i);
         ++(rr->names[0]);
         rr->names[rr->names[0]] = name_num;
         ++name_num;
  }
  if (byte_equal(rr->type,2,DNS_T_TXT)) {
         rr->other = alloc(((unsigned char)rptr[i])+1); 
         for (j=0;j <= ((unsigned char)rptr[i]);++j) *(rr->other+j) = rptr[i+j];
  }

  *pos = i;
}

void write_resource_rec(rrec rr) {
  unsigned int i=1,pos,l;
  char *dname;

  str_to_name(names[rr.names[i]],&dname);
  response_addname(dname);
  ++i;
  response_addbytes(rr.type,2);
  response_addbytes(rr.class,2);
  response_addbytes(rr.ttl,4);
  response_addbytes(rr.rlength,2);
  pos = response_len;
  if (byte_equal(rr.type,2,DNS_T_A)) {
    response_addbytes(rr.other,4);
    alloc_free(rr.other);
  }
  if (byte_equal(rr.type,2,DNS_T_NS) ||
      byte_equal(rr.type,2,DNS_T_CNAME) ||
      byte_equal(rr.type,2,DNS_T_PTR)) {
    str_to_name(names[rr.names[i]],&dname);
    response_addname(dname);
  }
  if (byte_equal(rr.type,2,DNS_T_SOA)) {
    str_to_name(names[rr.names[i]],&dname);
    ++i;
    response_addname(dname);
    str_to_name(names[rr.names[i]],&dname);
    ++i;
    response_addname(dname);
    response_addbytes(rr.other,20);
    alloc_free(rr.other);
  }
  if (byte_equal(rr.type,2,DNS_T_MX)) {
    response_addbytes(rr.other,2);
    str_to_name(names[rr.names[i]],&dname);
    response_addname(dname);
    alloc_free(rr.other);
  }
  if (byte_equal(rr.type,2,DNS_T_TXT)) {
    l = 256 * (unsigned char)rr.rlength[0] + (unsigned char)rr.rlength[1];
    response_addbytes(rr.other,l);
    alloc_free(rr.other);
  }

  response[pos-2] = (char)((response_len-pos) / 256);
  response[pos-1] = (char)((response_len-pos) % 256);
}

void get_query_rec_at_pos(char *rptr,unsigned int *pos,char *qname,char qtype[2],char qclass[2]) {
  unsigned int i = *pos;

  i += get_name_at_pos(rptr,qname,i);
  qtype[0] = rptr[i++]; qtype[1] = rptr[i++];
  qclass[0] = rptr[i++]; qclass[1] = rptr[i++];
  *pos = i;
}

prule_ptr match_rule(char ip[4],char type[2],char* s) {
  prule_ptr actual = first;
  regex_eptr act_rx;
  int match;
  int i = 0;
  unsigned char ip_[4];
 
  ip_[0] = ip[0]; ip_[1] = ip[1]; ip_[2] = ip[2]; ip_[3] = ip[3];

  while (actual != NULL) {
    ++i;
    match = 1;

    if (!match_ip(ip,actual->ipl,actual->ipu)) match = 0;

    if (!(actual->type[0] == '\1' && actual->type[1] == '\1') &&
        !(actual->type[0] == type[0] && actual->type[1] == type[1])) match = 0;

    if (match) {
       act_rx = actual->first_regex;
       if (act_rx->next_regex == NULL) {
        if (regexec(act_rx->re,s,(size_t)0,NULL,0) == 0) return actual;
       }
       else { return NULL; /* XXX - sub regexps not supported yet */ }
    }
    actual = actual->next;
  }
  return NULL;
}

int make_answer(prule_ptr rule,rrec rr) {
  char *dname;
  unsigned int rlen;

  str_to_name(names[0],&dname);
  response_addname(dname);
  response_addbytes(rule->type2,2);
  response_addbytes("\0\1",2);
  if (rule->match_ttl) response_addbytes(rule->ttl,4); else response_addbytes(rr.ttl,4);
  response_addbytes(rule->rlength,2);
  rlen = 256 * (unsigned char)rule->rlength[0] + (unsigned char)rule->rlength[1];
  response_addbytes(rule->rdata,rlen);
  return 1;
}

// rewrite DNS response packet's content according to the rulebase
void convert(char ip[4],unsigned int rlen,char *rptr) {
  prule_ptr rule = NULL;
  char qtype[2],qclass[2],header[12];
  char *qn;
  unsigned int i,j;

  name_num = 0;
  rec_num = 0;

  for(i=0;i<12;++i) header[i] = rptr[i];
  qdcount = 256 * header[4] + header[5];
  ancount = 256 * header[6] + header[7];
  nscount = 256 * header[8] + header[9];
  arcount = 256 * header[10] + header[11];

  for (j=0;j < qdcount;++j) {
    get_query_rec_at_pos(rptr,&i,names[name_num],qtype,qclass);
    rule = match_rule(ip,qtype,names[name_num]);
  }
  if (rule == NULL) return;
  ++name_num;

  for (j=0;j < ancount;++j) {
    get_resource_rec_at_pos(rptr,&i,&(rrecords[rec_num]));
    ++rec_num;
  }
  first_ns = rec_num;

  for(j=0;j < nscount;++j) {
    get_resource_rec_at_pos(rptr,&i,&(rrecords[rec_num]));
    ++rec_num;
  }
  for(j=0;j < arcount;++j) {
    get_resource_rec_at_pos(rptr,&i,&(rrecords[rec_num]));
    ++rec_num;
  }

  str_to_name(names[0],&qn);
  response_query(qn,qtype,qclass);

  for (j=0;j < 12;++j) response[j]=header[j];

  if (rule->nxdomain) { response[6]='\0'; response[7]='\0';  
                        response_nxdomain();
                      }
  else { 
    if (rule->type2[0] == '\1' && rule->type2[0] == '\1')
       for (j=0;j < ancount;++j) {
             if (rule->match_ttl) 
               byte_copy(rrecords[j].ttl, 4, rule->ttl);
             write_resource_rec(rrecords[j]);
       }
    else {
       make_answer(rule,rrecords[0]);
       response[6]='\0'; response[7]='\1';
    }
  }
    
  for(j=0;j < nscount;++j)
    write_resource_rec(rrecords[first_ns+j]);

  for(j=0;j < arcount;++j)
    write_resource_rec(rrecords[first_ns+nscount+j]);
}

int build_rulebase(const char *config_file) {
  char line[1000];
  int i = 1;

  FILE *fd;
  prule_ptr fir = NULL,actual;
  fd = fopen(config_file,"r");
  if (fd == NULL) return -1;

  if (fgets(line,1000,fd) != NULL && line[0] != '#') {
      fir = make_rule(line);
      if (fir == NULL) return i;
  }
  actual = fir;
  while (fgets(line,1000,fd) != NULL) {
   ++i;
   if (line[0] != '#') {
    if (actual == NULL) { fir = make_rule(line); actual = fir;
                          if (actual == NULL) return i;
                        }
    else { actual->next = make_rule(line);
           if (actual->next == NULL) return i;
           actual = actual->next;
         }
   }
  }
  fclose(fd);
  first = fir;
  return 0;
}

/* XXX - actually never invoked, dnscache doesn't have any
         termination points, it runs in an infinite loop */
void free_rules(/*prule_ptr first*/) {
  prule_ptr act1, act2;
  regex_eptr r1,r2;
  act1 = first;
  while (act1 != NULL) {
   r1 = act1->first_regex;
   while (r1 != NULL) {
     r2 = r1->next_regex;
     regfree(r1->re);
     free(r1);
     r1 = r2;
   }
   free(act1->rdata);
   act2 = act1->next;
   free(act1);
   act1 = act2;
  }
}
