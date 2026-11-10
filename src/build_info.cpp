#include "netscope/build_info.h"

#include <pcap/pcap.h>

#include <QtCore/qglobal.h>

namespace netscope {

build_info current_build_info() {
    const char* const pcap_version = pcap_lib_version();

    return build_info{
        qVersion(),
        pcap_version == nullptr ? std::string{} : std::string{pcap_version},
    };
}

}  // namespace netscope

