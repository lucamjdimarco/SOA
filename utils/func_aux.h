//#ifdef _FUNC_AUX_H_
//#define _FUNC_AUX_H_

int strncmp_custom(const char *s1, const char *s2, size_t n);

char *find_directory(char *path);
char *full_path(int dfd, const __user char *user_path);
char *get_pwd(void);

//#endif