//#ifndef FUNC_AUX_H
//#define FUNC_AUX_H

char *find_directory(char *path);
char *full_path(int dfd, const __user char *user_path);
char *get_pwd(void);
char *get_absolute_path(const char *user_path);

//#endif