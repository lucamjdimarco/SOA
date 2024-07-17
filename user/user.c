#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>

#define DEVICE_NAME "/dev/ref_monitor"

void display_menu() {
    printf("Select an operation:\n");
    printf("1. Monitor ON\n");
    printf("2. Monitor OFF\n");
    printf("3. Monitor REC_ON\n");
    printf("4. Monitor REC_OFF\n");
    printf("5. Change Password\n");
    printf("6. Insert Path\n");
    printf("7. Remove Path\n");
    printf("0. Exit\n");
    printf("Enter your choice: ");
}

void get_password(char *password, size_t size) {
    struct termios oldt, newt;
    int ch;
    size_t i = 0;

    // Disabilita l'eco del terminale
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);

    // Legge password
    while ((ch = getchar()) != '\n' && ch != EOF && i < size - 1) {
        password[i++] = ch;
    }
    password[i] = '\0';

    // Ripristina le impostazioni del terminale
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");
}

int main() {
    int fd, choice;
    ssize_t ret;
    char buffer[2048];
    char command[10];
    char password[100];
    char parameter[100];

    fd = open(DEVICE_NAME, O_WRONLY);
    if (fd < 0) {
        perror("Failed to open the device");
        return -1;
    }

    while (1) {
        display_menu();
        scanf("%d", &choice);
        getchar(); // consume the newline character

        if (choice == 0) {
            break;
        }

        printf("Enter password: ");
        // fgets(password, sizeof(password), stdin);
        // password[strcspn(password, "\n")] = 0; // remove the newline character
        get_password(password, sizeof(password));

        switch (choice) {
            case 1:
                snprintf(command, sizeof(command), "ON");
                snprintf(buffer, sizeof(buffer), "%s:%s", command, password);
                break;
            case 2:
                snprintf(command, sizeof(command), "OFF");
                snprintf(buffer, sizeof(buffer), "%s:%s", command, password);
                break;
            case 3:
                snprintf(command, sizeof(command), "REC_ON");
                snprintf(buffer, sizeof(buffer), "%s:%s", command, password);
                break;
            case 4:
                snprintf(command, sizeof(command), "REC_OFF");
                snprintf(buffer, sizeof(buffer), "%s:%s", command, password);
                break;
            case 5:
                snprintf(command, sizeof(command), "CHGPASS");
                printf("Enter new password: ");
                fgets(parameter, sizeof(parameter), stdin);
                parameter[strcspn(parameter, "\n")] = 0; // remove the newline character
                snprintf(buffer, sizeof(buffer), "%s:%s:%s", command, password, parameter);
                break;
            case 6:
                snprintf(command, sizeof(command), "INSERT");
                printf("Enter path to insert: ");
                fgets(parameter, sizeof(parameter), stdin);
                parameter[strcspn(parameter, "\n")] = 0; // remove the newline character
                snprintf(buffer, sizeof(buffer), "%s:%s:%s", command, password, parameter);
                break;
            case 7:
                snprintf(command, sizeof(command), "REMOVE");
                printf("Enter path to remove: ");
                fgets(parameter, sizeof(parameter), stdin);
                parameter[strcspn(parameter, "\n")] = 0; // remove the newline character
                snprintf(buffer, sizeof(buffer), "%s:%s:%s", command, password, parameter);
                break;
            default:
                printf("Invalid choice. Please try again.\n");
                continue;
        }

        ret = write(fd, buffer, strlen(buffer));
        if (ret < 0) {
            perror("Failed to write the message to the device");
            close(fd);
            return -1;
        }
    }

    close(fd);
    return 0;
}
