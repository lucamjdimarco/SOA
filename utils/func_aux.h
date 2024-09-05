//#ifndef FUNC_AUX_H
//#define FUNC_AUX_H


//int strncmp_custom(const char *s1, const char *s2, size_t n);

char *find_directory(char *path);
char *full_path(int dfd, const __user char *user_path);
char *get_pwd(void);
char *get_absolute_path(const char *user_path);
//int is_directory(const char *path);

//#endif