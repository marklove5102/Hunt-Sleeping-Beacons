#include <span>
#include <string>
#include <iostream>
#include <format>

#include "phnt.h"
#include "misc.hpp"
#include "scans.hpp"

namespace hsb::scanning {

	static constexpr std::array<std::uint8_t, 2> patternJmpDerefRbx = {0xFF, 0x23};
	static constexpr std::array<std::uint8_t, 3> patternJmpDerefRbp = {0xFF, 0x65, 0x00};
	static constexpr std::array<std::uint8_t, 2> patternJmpDerefRdi = {0xFF, 0x27};
	static constexpr std::array<std::uint8_t, 2> patternJmpDerefRsi = {0xFF, 0x26};
	static constexpr std::array<std::uint8_t, 4> patternJmpDerefR12 = {0x41, 0xff, 0x24, 0x24};
	static constexpr std::array<std::uint8_t, 4> patternJmpDerefR13 = {0x41, 0xff, 0x65, 0x00};
	static constexpr std::array<std::uint8_t, 3> patternJmpDerefR14 = {0x41, 0xff, 0x26};
	static constexpr std::array<std::uint8_t, 3> patternJmpDerefR15 = {0x41, 0xff, 0x27};

	thread_scan thread_scans::return_address_spoofing = [](process* process, thread* thread) {


		BOOL bSuspicious = FALSE, bSuccess = FALSE;
		SIZE_T nRead = 0, s = 0;

		std::array<std::uint8_t, 4> instructions = {};

		for(int i = 0; i < thread->calltrace->raw_addresses.size(); i++)
		{

			bSuspicious = false;

			for(int j = 0; j < 4; j++)
			{

				bSuccess = ReadProcessMemory(process->handle, (PVOID)(thread->calltrace->raw_addresses.at(i) + j), instructions.data(), sizeof(instructions), &nRead);
				if(bSuccess == FALSE)
					goto Cleanup;

				if(memcmp(instructions.data(), patternJmpDerefRbx.data(), sizeof(patternJmpDerefRbx)) == 0)
					bSuspicious = TRUE;
				else if(memcmp(instructions.data(), patternJmpDerefRbp.data(), sizeof(patternJmpDerefRbp)) == 0)
					bSuspicious = TRUE;
				else if(memcmp(instructions.data(), patternJmpDerefRdi.data(), sizeof(patternJmpDerefRdi)) == 0)
					bSuspicious = TRUE;
				else if(memcmp(instructions.data(), patternJmpDerefRsi.data(), sizeof(patternJmpDerefRsi)) == 0)
					bSuspicious = TRUE;
				else if(memcmp(instructions.data(), patternJmpDerefR12.data(), sizeof(patternJmpDerefR12)) == 0)
					bSuspicious = TRUE;
				else if(memcmp(instructions.data(), patternJmpDerefR13.data(), sizeof(patternJmpDerefR13)) == 0)
					bSuspicious = TRUE;
				else if(memcmp(instructions.data(), patternJmpDerefR14.data(), sizeof(patternJmpDerefR14)) == 0)
					bSuspicious = TRUE;
				else if(memcmp(instructions.data(), patternJmpDerefR15.data(), sizeof(patternJmpDerefR15)) == 0)
					bSuspicious = TRUE;

				if(bSuspicious) {

					thread_detection detection;
					detection.name = L"Return Address Spoofing";
					detection.description = std::format(L"Thread {} returns to JMP gadget. Gadget in: {}", thread->tid, misc::string_to_wstring(thread->calltrace->syms.at(i)));
					detection.tid = thread->tid;
					detection.severity = hsb::containers::detections::CRITICAL;

					process->add_detection(detection);

					break;

				}

			}
		}

	Cleanup:

		return;

		};

}