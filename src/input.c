#include <stdio.h>
#include <unistd.h>
#include <termios.h>

static struct termios old_term, new_term;

void init_input(){
	tcgetattr(STDIN_FILENO, &old_term);
	new_term = old_term;
	new_term.c_lflag &= ~(ECHO | ICANON); // input non visible, pas besoin de retour chariot pour envoyer le msg
}

char event_key(){
	char key_press = 0;
	// printf("izi");
	tcsetattr(STDIN_FILENO, TCSANOW, &new_term);
	key_press = getchar();
	// read(STDIN_FILENO, &key_press, sizeof(char)); // On lit le caractère pressed
	// tcflush(STDIN_FILENO, TCIFLUSH); // pour éviter de multiple impression de "Usage" lorsqu'on appuit par exemple sur les fleches du clavier
	tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
	return key_press;
}
