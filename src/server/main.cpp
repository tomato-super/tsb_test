#include "vmpq_server.hpp"
#include "vmpq_service.hpp"
#include "json.hpp"
#include <iostream>
#include <fstream>

using json = nlohmann::json;

struct cfgInfo{ 
    int server_id;
    std::string port;
};

void param_eval(std::string json_path, cfgInfo& cfg) {

    auto file = std::ifstream(json_path);
    if(!file.is_open()) {
        throw std::runtime_error("can't open config: " + json_path);
    }

    auto json_cfg = json::parse(file);

    cfg.server_id = json_cfg["server_id"];
    cfg.port = json_cfg["host_port"];
}


int main(int argc, char const *argv[]) {

    if(argc < 2) {
        std::cerr << "Usage: ./vmpq_server <config_path>" << std::endl;
        return EXIT_FAILURE;
    }

    cfgInfo cfg;
    param_eval(argv[1], cfg);

    VMPQServer server(cfg.server_id);
    VMPQServiceImpl service(server);

    grpc::ServerBuilder builder;
    builder.AddListeningPort(
        "0.0.0.0:" + cfg.port, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);

    grpc::EnableDefaultHealthCheckService(true);

    auto srv = builder.BuildAndStart();
    if(!srv) {
        std::cerr << "Failed to start  server" << std::endl;
        return EXIT_FAILURE;
    }
    
    auto health_service = srv->GetHealthCheckService();
    health_service->SetServingStatus("VMPQ.VMPQService", true);

    std::cout << "[Server] id=" << cfg.server_id 
          << " listening on 0.0.0.0:" << cfg.port << std::endl;

    srv->Wait();

    return 0;
}
