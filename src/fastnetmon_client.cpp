#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <thread>
#include <chrono>

#ifdef _WIN32
// msys2 and mingw use nested path for some reasons but Linux keeps it in include directly: https://packages.msys2.org/package/mingw-w64-x86_64-ncurses
// On Windows we do only static builds to avoid carrying bunch of dlls with us
#define NCURSES_STATIC
#include <ncurses/ncurses.h>
#else
#include <ncurses.h>
#endif

#include <boost/program_options.hpp>

std::string cli_stats_ipv4_file_path = "/tmp/fastnetmon.dat";

std::string cli_stats_ipv6_file_path = "/tmp/fastnetmon_ipv6.dat";

std::string format_fastnetmon_client_header(const std::string& header) {
    const std::string upstream_prefix = "FastNetMon ";
    const std::string advanced_edition_suffix = " Try Advanced edition: https://fastnetmon.com/product-overview/";

    if (header.rfind(upstream_prefix, 0) != 0) {
        return header;
    }

    const size_t suffix_position = header.find(advanced_edition_suffix, upstream_prefix.size());
    if (suffix_position == std::string::npos) {
        return header;
    }

    return "FastNetMon Biba Edition "
           + header.substr(upstream_prefix.size(), suffix_position - upstream_prefix.size());
}

int main(int argc, char** argv) {
    bool ipv6_mode = false;

    namespace po = boost::program_options;

    try {
        // clang-format off
        po::options_description desc("Allowed options");
        desc.add_options()
        ("help", "produce help message")
        ("ipv6", "switch to IPv6 mode");
        // clang-format on

        po::variables_map vm;
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);

        if (vm.count("help")) {
            std::cout << desc << std::endl;
            exit(EXIT_SUCCESS);
        }

        if (vm.count("ipv6")) {
            ipv6_mode = true;
        }
    } catch (po::error& e) {
        std::cerr << "ERROR: " << e.what() << std::endl << std::endl;
        exit(EXIT_FAILURE);
    }

    // Init ncurses screen
    initscr();

    // disable any character output
    noecho();

    // hide cursor
    curs_set(0);

    // Do not wait for getch
    timeout(0);

    while (true) {
        std::this_thread::sleep_for (std::chrono::seconds(1));

        // clean up screen
        clear();

        int c = getch();

        if (c == 'q') {
            endwin();
            exit(0);
        }


        std::string cli_stats_file_path = cli_stats_ipv4_file_path;

        if (ipv6_mode) {
            cli_stats_file_path = cli_stats_ipv6_file_path;
        }

        char* cli_stats_file_path_env = getenv("cli_stats_file_path");

        if (cli_stats_file_path_env != NULL) {
            cli_stats_file_path = std::string(cli_stats_file_path_env);
        }

        std::ifstream reading_file;
        reading_file.open(cli_stats_file_path.c_str(), std::ifstream::in);

        if (!reading_file.is_open()) {
            std::string error_message = "Can't open fastnetmon stats file: " + cli_stats_file_path;

            addstr(error_message.c_str());

            // update screen
            refresh();
            continue;
        }

        std::string line = "";
        std::stringstream screen_buffer;
        bool first_line = true;
        while (getline(reading_file, line)) {
            if (first_line) {
                screen_buffer << format_fastnetmon_client_header(line) << "\n";
                first_line = false;
                continue;
            }

            screen_buffer << line << "\n";
        }

        reading_file.close();

        addstr(screen_buffer.str().c_str());
        // update screen
        refresh();
    }

    /* End ncurses mode */
    endwin();
}
