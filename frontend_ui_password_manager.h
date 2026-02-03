//Frontend logic of my password manager:
//TODO: Separate the Frontend logic to header and cpp
//80%ready!
#ifndef FRONTEND_UI_PASSWORD_MANAGER_H
#define FRONTEND_UI_PASSWORD_MANAGER_H

#include "backend.h"

extern void textInRed(const char* text);
class LoginBar {
private:
	char nameInputBuffer[20];
	char passwordInputBuffer[20];

	bool showMessage = false;
	bool verify = false;
	Backend program_backend;
	
public:
	enum class Login_State {
		Enter_Userame_Password,
		Logged_In
	};

	Login_State login_status = Login_State::Enter_Userame_Password;
	void drawLoginBar(char* name, size_t nameSize);
};
class RegistrationBar {
private:
	char nameInputBuffer[20];
	char passwordInputBuffer[20];
	char reEnterPasswordBuffer[20];
	char keyInputBuffer[20];

	bool showWrongPasswordMessage = false;
	bool showExistingUsernameMessage = false;
	Backend program_backend;

	void drawTextBuffers();
public:
	enum class Register_State {
		Enter_Name_Password,
		Create_Key,
		Logged_In
	};
	Register_State register_state = Register_State::Enter_Name_Password;
	void drawRegistrationBar(char* name, size_t nameSize);
};
//clas for ui:
class Program {
private:
	char enterKeyInput[20];
	char name[20];
	char label[20];
	char label_password[20];

	bool logIn = false;
	bool registration = false;
	bool showText = false;
	bool showPasswords = false;
	bool vault_unlocked = false;
	
	
	RegistrationBar registration_bar;
	Backend program_backend;
	LoginBar loginbar;

	void drawPasswordsChild();
public:
	void drawUI(bool& open);
};
#endif