//Init sodium class:
#ifndef SODIUM_INIT_H
#define SODIUM_INIT_H
#include <sodium.h>
#include <stdexcept>
#include "imgui.h"

//Sodium initialise RAII struct:
struct Sodium_Init {
	Sodium_Init() {
		if (sodium_init() < 0) {
			IM_ASSERT(false && "Sodium initialise failed");
			std::abort();
		}
	}
	~Sodium_Init() = default;
	Sodium_Init(const Sodium_Init& other) = delete;
	Sodium_Init& operator = (const Sodium_Init& other) = delete;
};
#endif
