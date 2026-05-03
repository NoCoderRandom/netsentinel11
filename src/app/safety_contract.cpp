#include "safety_contract.h"

#include <iomanip>
#include <iostream>

namespace netsentinel::app {

void print_safety_contract(std::ostream& out) {
    out << "NetSentinel11 safety contract:\n";
    out << "- Use on networks you own or have explicit authorization for.\n";
    out << "- Default scope is local/subnet only.\n";
    out << "- No exploitation, credential attacks, or traffic disruption methods.\n";
    out << "- No ARP spoofing, deauth, MITM, stealth, or packet injection.\n";
    out << "- Optional integrations must be transparent, reversible, and consented.\n";
    out << "- Any non-local-scope scan requires explicit confirmation in the UI/CLI.\n";
}

} // namespace netsentinel::app

