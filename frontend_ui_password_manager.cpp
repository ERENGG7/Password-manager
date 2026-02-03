
#include "frontend_ui_password_manager.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx9.h"
#include "imgui.h"
#include "backend.h"
#include <cstring>
#include <vector>
#include <stdio.h>

void textInRed(const char* text) {
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 0.0f, 0.0f, 1.0f));
	ImGui::Text("%s", text);
	ImGui::PopStyleColor();
}
void  LoginBar::drawLoginBar(char* name, size_t nameSize) {
	/*bool verify = false;*/
	ImGui::PushID("Login bar");
	ImGui::BeginChild("Log in", ImVec2(300, 226), false);
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 0.0f, 1.0f));
	ImGui::Text("Enter username:");
	ImGui::PushItemWidth(265);
	ImGui::PushID("log in name");
	ImGui::InputText("", nameInputBuffer, sizeof(nameInputBuffer));
	ImGui::PopID();
	ImGui::Text("Enter password:");
	ImGui::PushID("log in password");
	ImGui::InputText("",
		passwordInputBuffer,
		sizeof(passwordInputBuffer),
		ImGuiInputTextFlags_Password);
	ImGui::PopID();
	ImGui::PopStyleColor();
	ImGui::PopItemWidth();
	//Button enter:
	if (strlen(nameInputBuffer) > 0 && strlen(passwordInputBuffer) > 0) {
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.0f, 0.0f, 0.5f, 1.0f));
		if (ImGui::Button("Enter")) {
			verify = program_backend.log_in(nameInputBuffer, passwordInputBuffer);
			if (verify) {
				login_status = Login_State::Logged_In;
				sprintf_s(name, nameSize, "%s", nameInputBuffer);
				showMessage = program_backend.log_in(nameInputBuffer, passwordInputBuffer);
			}
			else { showMessage = true; }
			sodium_memzero(passwordInputBuffer, sizeof(passwordInputBuffer));
			memset(nameInputBuffer, 0, sizeof(nameInputBuffer));
		}
		ImGui::PopStyleColor();
	}
	if (showMessage) {
		textInRed("Wrong username or password");
	}
	ImGui::EndChild();
	ImGui::PopID();
}
void RegistrationBar::drawTextBuffers() {
	ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 0.0f, 1.0f));
	ImGui::PushItemWidth(265);
	ImGui::Text("Create username: ");
	ImGui::PushID("registration name");
	ImGui::InputText("", nameInputBuffer, sizeof(nameInputBuffer));
	ImGui::PopID();
	ImGui::Text("Enter password:");
	//password buffer:
	ImGui::PushID("registration password");
	ImGui::InputText("",
		passwordInputBuffer,
		sizeof(passwordInputBuffer),
		ImGuiInputTextFlags_Password);
	ImGui::PopID();
	ImGui::Text("Reenter password:");
	//re-enter password buffer:
	ImGui::PushID("registration re enter password");
	ImGui::InputText("",
		reEnterPasswordBuffer,
		sizeof(reEnterPasswordBuffer),
		ImGuiInputTextFlags_Password);
	ImGui::PopID();
	ImGui::PopStyleColor();
	ImGui::PopItemWidth();
}

void RegistrationBar::drawRegistrationBar(char* name, size_t nameSize) {
	ImGui::PushID("Registration bar");
	ImGui::BeginChild("Registration", ImVec2(300, 226), false);
	if (register_state == Register_State::Enter_Name_Password) {
		drawTextBuffers();
		//Button enter:
		//Button-hovered dark blue
		ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.0f, 0.0f, 0.5f, 1.0f));
		if (strlen(passwordInputBuffer) > 0
			&& strlen(nameInputBuffer) > 0
			&& strlen(reEnterPasswordBuffer) > 0) {
			if (ImGui::Button("Enter")) {

				if (strcmp(passwordInputBuffer,
					reEnterPasswordBuffer) != 0) {
					showWrongPasswordMessage = true;
					sodium_memzero(passwordInputBuffer, sizeof(passwordInputBuffer));
					sodium_memzero(reEnterPasswordBuffer, sizeof(reEnterPasswordBuffer));
				}
				else {
					showWrongPasswordMessage = false;
					sprintf_s(name, nameSize, "%s", nameInputBuffer);
					memset(nameInputBuffer, 0, sizeof(nameInputBuffer));
					register_state = Register_State::Create_Key;
				}

			}
		}
		ImGui::PopStyleColor();
		if (showWrongPasswordMessage) {
			textInRed("Passwords do not match");
		}
	}
	if (register_state == Register_State::Create_Key) {
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 0.0f, 1.0f));
		ImGui::Text("Enter unique key to see\nall the passwords");
		//Enter unique key:
		ImGui::PushID("Enter key");
		ImGui::InputText("", keyInputBuffer, sizeof(keyInputBuffer), ImGuiInputTextFlags_Password);
		ImGui::PopID();
		ImGui::PopStyleColor();
		if (ImGui::Button("Enter")) {
			//TODO: Enkrypt the keywith void function from backend functions!		
			if (program_backend.registration(name, passwordInputBuffer, keyInputBuffer)) {
				register_state = Register_State::Logged_In;
				showExistingUsernameMessage = false;
			}
			else {
				showExistingUsernameMessage = true;
			}
			sodium_memzero(passwordInputBuffer, sizeof(passwordInputBuffer));
			sodium_memzero(reEnterPasswordBuffer, sizeof(reEnterPasswordBuffer));
			sodium_memzero(keyInputBuffer, sizeof(keyInputBuffer));
		}
	}
	if (showExistingUsernameMessage) {
		textInRed("User with this\nusername already existis");
		if (ImGui::Button("Begin")) {
			register_state = Register_State::Enter_Name_Password;
			showExistingUsernameMessage = false;
		}
	}
	ImGui::EndChild();
	ImGui::PopID();
}

void Program::drawPasswordsChild() {
	//ImGui::ChildWindow:
	ImGui::PushStyleColor(ImGuiCol_ChildBg, ImVec4(0.15f, 0.15f, 0.25f, 1.0f));
	ImGui::BeginChild("passwords", ImVec2(310, 340), true);
	if (vault_unlocked) {
		auto decrypted_passwords = program_backend.get_passwords(name);
		if (!decrypted_passwords.empty()) {
			ImGui::BeginDisabled();
			for (int i = 0; i < decrypted_passwords.size(); i++) {
				ImGui::PushID(i);
				std::string display_text = decrypted_passwords[i].first + ": " + decrypted_passwords[i].second;
				ImGui::Button(display_text.c_str(), ImVec2(289, 30));
				ImGui::PopID();
			}
			ImGui::EndDisabled();
		}
	}
	ImGui::EndChild();
}

void Program::drawUI(bool& open) {
	ImGui::SetNextWindowBgAlpha(0.7f);
	ImGui::SetNextWindowSize(ImVec2(623, 384), ImGuiCond_Always);
	ImGui::Begin("Password manager", &open, ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse);
	if (registration_bar.register_state
		!= RegistrationBar::Register_State::Logged_In
		&& loginbar.login_status
		!= LoginBar::Login_State::Logged_In) {

		if (ImGui::Button("Log in", ImVec2(160, 30))) {
			logIn = true;
			registration = !logIn;
		}
		if (ImGui::Button("Registration", ImVec2(160, 30))) {
			registration = true;
			logIn = !registration;
		}
		if (logIn) { loginbar.drawLoginBar(name, sizeof(name)); }
		if (registration) { registration_bar.drawRegistrationBar(name, sizeof(name)); } //send to .json
	}
	if (registration_bar.register_state == RegistrationBar::Register_State::Logged_In
		|| loginbar.login_status == LoginBar::Login_State::Logged_In) {
		logIn = false;
		registration = false;

		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 0.0f, 1.0f));
		ImGui::Text("Logged in. Hello %s", name);
		ImGui::Text("Enter key password to\nsee all of\nyour passwords:");
		ImGui::PushItemWidth(270);
		ImGui::PushID("Key input loged in");
		ImGui::BeginDisabled(showPasswords);
		ImGui::InputText("",
			enterKeyInput,
			sizeof(enterKeyInput),
			ImGuiInputTextFlags_Password);
		ImGui::PopStyleColor();
		ImGui::PopItemWidth();
		ImGui::PopID();

		if (ImGui::Button("Enter")) {
			if (program_backend.unlock_vault(name, enterKeyInput)) {
				vault_unlocked = true;
				showPasswords = true;
				showText = false;
				memset(label, 0, sizeof(label));
				sodium_memzero(label_password, sizeof(label_password));
			}
			else {
				showText = true; // Wrong key!
				sodium_memzero(enterKeyInput, sizeof(enterKeyInput));
			}
		}
		ImGui::EndDisabled();
		if (showText) {
			textInRed("Wrong key!");
		}
		ImGui::SetCursorPos(ImVec2(300, 34));
		//ImGui::ChildWindow: 
		drawPasswordsChild();
		//TODO: Create backend function for encrypt:
		ImGui::PopStyleColor();

		ImGui::SetCursorPos(ImVec2(10, 235));
		ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 0.0f, 1.0f));
		ImGui::Text("Add password:");
		ImGui::Text("Website or label:");
		ImGui::PushItemWidth(270);
		ImGui::PushID("label");
		ImGui::InputText("", label, sizeof(label));
		ImGui::PopID();
		ImGui::PushID("password");
		ImGui::InputText("",
			label_password,
			sizeof(label_password),
			ImGuiInputTextFlags_Password);

		ImGui::PopID();
		ImGui::PopStyleColor();
		ImGui::PopItemWidth();
		if (strlen(label) > 0 && strlen(label_password) > 0) {
			if (ImGui::Button("Add")) {
				if (!vault_unlocked) {
					if (!program_backend.unlock_vault(name, enterKeyInput)) {
						showText = true;
						return;
					}
					vault_unlocked = true;
					showPasswords = true;
				}
				program_backend.add_password(name, label, label_password);
				memset(label, 0, sizeof(label));
				sodium_memzero(label_password, 0, sizeof(label_password));
			}
		}
	}
	ImGui::End();

    if (!open) {
	    sodium_memzero(enterKeyInput, sizeof(enterKeyInput));
    }
}
