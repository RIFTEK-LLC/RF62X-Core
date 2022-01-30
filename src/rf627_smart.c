#include "rf62X_sdk.h"

#include <stdarg.h>
#include <stdio.h>
#include <time.h>

#include <mpack/mpack.h>

#include "iostream_platform.h"
#include "netwok_platform.h"
#include "memory_platform.h"
#include "custom_string.h"
#include "utils.h"

#include "RF62Xchannel.h"
#include "RF62Xtypes.h"


// Global variables.
int answ_count = 0; ///< Answer counter
vector_t *search_history = NULL; ///< Search history
vector_t *current_search_result = NULL; ///< Current search result

/**
 * @brief generate_config_string - generate config string for RF62X-Protocol
 * @return config string.
 */
char* generate_config_string(
        uint32_t host_device_uid, char* host_ip_addr, char* dst_ip_addr,
        uint32_t host_udp_port, uint32_t dst_udp_port, uint32_t socket_timeout,
        uint32_t max_packet_size, uint32_t max_data_size);



rf627_smart_t* rf627_smart_create_from_hello_msg(char* data, rfUint32 data_size)
{
    rf627_smart_t* rf627_smart = memory_platform.rf_calloc(1, sizeof (rf627_smart_t));
    memset(rf627_smart, 0, sizeof (rf627_smart_t));
    rf627_smart->is_connected = FALSE;
    vector_init(&rf627_smart->params_list);
    vector_init(&rf627_smart->protocol_settings_list);
    pthread_mutex_init(&rf627_smart->protocol_settings_mutex, NULL);

    int32_t result = FALSE;

    // Get params
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        result = FALSE;
        mpack_tree_destroy(&tree);
        return NULL;
    }
    mpack_node_t root = mpack_tree_root(&tree);

    // Device firmware version [Major, Minor, Patch].
    if (mpack_node_map_contains_cstr(root, "fact_general_firmwareVer"))
    {
        for(size_t i = 0; i < mpack_node_array_length(mpack_node_map_cstr(root, "fact_general_firmwareVer")); i++)
        {
            rf627_smart->info_by_service_protocol.fact_general_firmwareVer[i] =
                    mpack_node_uint(mpack_node_array_at(mpack_node_map_cstr(root, "fact_general_firmwareVer"), i));
        }
    }

    // Device hardware version.
    if (mpack_node_map_contains_cstr(root, "fact_general_hardwareVer"))
    {
        rf627_smart->info_by_service_protocol.fact_general_hardwareVer =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_hardwareVer"));
    }

    // Size of the measuring range in Z axis in mm.
    if (mpack_node_map_contains_cstr(root, "fact_general_mr"))
    {
        rf627_smart->info_by_service_protocol.fact_general_mr =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_mr"));
    }

    // Device type identifier.
    if (mpack_node_map_contains_cstr(root, "fact_general_productCode"))
    {
        rf627_smart->info_by_service_protocol.fact_general_productCode =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_productCode"));
    }

    // Device serial number.
    if (mpack_node_map_contains_cstr(root, "fact_general_serial"))
    {
        rf627_smart->info_by_service_protocol.fact_general_serial =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_serial"));
    }

    // Start of measuring range in Z axis in mm.
    if (mpack_node_map_contains_cstr(root, "fact_general_smr"))
    {
        rf627_smart->info_by_service_protocol.fact_general_smr =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_smr"));
    }

    // The size along the X axis of the measuring range at the beginning of the range.
    if (mpack_node_map_contains_cstr(root, "fact_general_xsmr"))
    {
        rf627_smart->info_by_service_protocol.fact_general_xsmr =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_xsmr"));
    }

    if (mpack_node_map_contains_cstr(root, "fact_general_xemr"))
    {
        rf627_smart->info_by_service_protocol.fact_general_xemr =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_xemr"));
    }

    // The wavelength of the laser, installed in the device.
    if (mpack_node_map_contains_cstr(root, "fact_laser_waveLength"))
    {
        rf627_smart->info_by_service_protocol.fact_laser_waveLength =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_laser_waveLength"));
    }

    // Physical address of the device.
    if (mpack_node_map_contains_cstr(root, "fact_network_macAddr"))
    {
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "fact_network_macAddr")) + 1;
        rf627_smart->info_by_service_protocol.fact_network_macAddr =
                mpack_node_cstr_alloc(mpack_node_map_cstr(root, "fact_network_macAddr"), type_strlen);
    }

    // User-defined scanner name. It is displayed on the web page of the scanner
    // and can be used to quickly identify scanners.
    if (mpack_node_map_contains_cstr(root, "user_general_deviceName"))
    {
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "user_general_deviceName")) + 1;
        rf627_smart->info_by_service_protocol.user_general_deviceName =
                mpack_node_cstr_alloc(mpack_node_map_cstr(root, "user_general_deviceName"), type_strlen);
    }

    // Turns on and off the automatic negotiation of the Ethernet connection speed.
    if (mpack_node_map_contains_cstr(root, "user_network_autoNeg"))
    {
        rf627_smart->info_by_service_protocol.user_network_autoNeg =
                mpack_node_bool(mpack_node_map_cstr(root, "user_network_autoNeg"));
    }

    // Gateway address.
    if (mpack_node_map_contains_cstr(root, "user_network_gateway"))
    {
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "user_network_gateway")) + 1;
        rf627_smart->info_by_service_protocol.user_network_gateway =
                mpack_node_cstr_alloc(mpack_node_map_cstr(root, "user_network_gateway"), type_strlen);
    }

    // Host address.
    if (mpack_node_map_contains_cstr(root, "user_network_hostIP"))
    {
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "user_network_hostIP")) + 1;
        rf627_smart->info_by_service_protocol.user_network_hostIP =
                mpack_node_cstr_alloc(mpack_node_map_cstr(root, "user_network_hostIP"), type_strlen);
    }

    // Turns on and off the automatic negotiation of the Ethernet connection speed.
    if (mpack_node_map_contains_cstr(root, "user_network_hostPort"))
    {
        rf627_smart->info_by_service_protocol.user_network_hostPort =
                mpack_node_uint(mpack_node_map_cstr(root, "user_network_hostPort"));
    }

    // The network address of the device
    if (mpack_node_map_contains_cstr(root, "user_network_ip"))
    {
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "user_network_ip")) + 1;
        rf627_smart->info_by_service_protocol.user_network_ip =
                mpack_node_cstr_alloc(mpack_node_map_cstr(root, "user_network_ip"), type_strlen);
    }

    // Subnet mask for the device
    if (mpack_node_map_contains_cstr(root, "user_network_mask"))
    {
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "user_network_mask")) + 1;
        rf627_smart->info_by_service_protocol.user_network_mask =
                mpack_node_cstr_alloc(mpack_node_map_cstr(root, "user_network_mask"), type_strlen);
    }

    // Port number for service protocol.
    if (mpack_node_map_contains_cstr(root, "user_network_servicePort"))
    {
        rf627_smart->info_by_service_protocol.user_network_servicePort =
                mpack_node_uint(mpack_node_map_cstr(root, "user_network_servicePort"));
    }

    // Current Ethernet connection speed. The connection speed is changed by writing
    // to this parameter. In case of auto-negotiation, writing is ignored.
    if (mpack_node_map_contains_cstr(root, "user_network_speed"))
    {
        rf627_smart->info_by_service_protocol.user_network_speed =
                mpack_node_uint(mpack_node_map_cstr(root, "user_network_speed"));
    }

    // Port number to access the Web page.
    if (mpack_node_map_contains_cstr(root, "user_network_webPort"))
    {
        rf627_smart->info_by_service_protocol.user_network_webPort =
                mpack_node_uint(mpack_node_map_cstr(root, "user_network_webPort"));
    }

    // Enabling and disabling the profile stream, transmitted via the UDP protocol
    // (sending to the network address, set by the user_network_hostIP parameter
    // and the port, set by the user_network_hostPort parameter).
    if (mpack_node_map_contains_cstr(root, "user_streams_udpEnabled"))
    {
        rf627_smart->info_by_service_protocol.user_streams_udpEnabled =
                mpack_node_bool(mpack_node_map_cstr(root, "user_streams_udpEnabled"));
    }

    // The format of the transmitted profiles.
    if (mpack_node_map_contains_cstr(root, "user_streams_format"))
    {
        rf627_smart->info_by_service_protocol.user_streams_format =
                mpack_node_uint(mpack_node_map_cstr(root, "user_streams_format"));
    }

    // The maxmim udp packet size.
    if (mpack_node_map_contains_cstr(root, "fact_serviceProtocol_maxPacketSize"))
    {
        rf627_smart->info_by_service_protocol.fact_maxPacketSize =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_serviceProtocol_maxPacketSize"));
    }else
    {
        rf627_smart->info_by_service_protocol.fact_maxPacketSize = 65535;
    }

    mpack_tree_destroy(&tree);

    return rf627_smart;

}
void rf627_smart_free(rf627_smart_t* scanner)
{
    for (rfUint32 i = 0; i < vector_count(search_history); i++)
    {
        if(((scanner_base_t*)vector_get(search_history, i))->type == kRF627_SMART)
        {
            uint32_t serial = ((scanner_base_t*)vector_get(search_history, i))->rf627_smart->info_by_service_protocol.fact_general_serial;
            if (serial == scanner->info_by_service_protocol.fact_general_serial)
            {
                RF62X_channel_cleanup(&scanner->channel);
                network_platform.network_methods.close_socket(scanner->m_data_sock);

                while (vector_count(scanner->params_list) > 0)
                {
                    parameter_t* p = vector_get(scanner->params_list, vector_count(scanner->params_list)-1);
                    free_parameter(p, kRF627_SMART);

                    vector_delete(scanner->params_list, vector_count(scanner->params_list)-1);
                }
                vector_free(scanner->params_list);

                pthread_mutex_lock(&scanner->protocol_settings_mutex);
                while (vector_count(scanner->protocol_settings_list) > 0)
                {
                    rf627_smart_protocol_cmd_settings_t* p = vector_get(scanner->protocol_settings_list, vector_count(scanner->protocol_settings_list)-1);
                    memory_platform.rf_free(p->cmd_name);
                    memory_platform.rf_free(p);

                    vector_delete(scanner->protocol_settings_list, vector_count(scanner->protocol_settings_list)-1);
                }
                vector_free(scanner->protocol_settings_list);
                pthread_mutex_unlock(&scanner->protocol_settings_mutex);

                if (scanner->info_by_service_protocol.user_general_deviceName != NULL)
                {
                    free (scanner->info_by_service_protocol.user_general_deviceName);
                    scanner->info_by_service_protocol.user_general_deviceName = NULL;
                }
                if (scanner->info_by_service_protocol.user_network_ip != NULL)
                {
                    free (scanner->info_by_service_protocol.user_network_ip);
                    scanner->info_by_service_protocol.user_network_ip = NULL;
                }
                if (scanner->info_by_service_protocol.user_network_mask != NULL)
                {
                    free (scanner->info_by_service_protocol.user_network_mask);
                    scanner->info_by_service_protocol.user_network_mask = NULL;
                }
                if (scanner->info_by_service_protocol.user_network_gateway != NULL)
                {
                    free (scanner->info_by_service_protocol.user_network_gateway);
                    scanner->info_by_service_protocol.user_network_gateway = NULL;
                }
                if (scanner->info_by_service_protocol.user_network_hostIP != NULL)
                {
                    free (scanner->info_by_service_protocol.user_network_hostIP);
                    scanner->info_by_service_protocol.user_network_hostIP = NULL;
                }
                if (scanner->info_by_service_protocol.user_network_hostIP != NULL)
                {
                    free (scanner->info_by_service_protocol.user_network_hostIP);
                    scanner->info_by_service_protocol.user_network_hostIP = NULL;
                }
                if (scanner != NULL)
                {
                    free (scanner);
                    scanner = NULL;
                }

                vector_delete(search_history, i);
            }
        }
    }



}

rfBool rf627_smart_update_from_hello_msg(char* data, rfUint32 data_size, rf627_smart_t* rf627_smart, rfBool* update_network)
{
    // Get params
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        mpack_tree_destroy(&tree);
        return FALSE;
    }
    mpack_node_t root = mpack_tree_root(&tree);

    *update_network = FALSE;
    // Device firmware version [Major, Minor, Patch].
    if (mpack_node_map_contains_cstr(root, "fact_general_firmwareVer"))
    {
        for(size_t i = 0; i < mpack_node_array_length(mpack_node_map_cstr(root, "fact_general_firmwareVer")); i++)
        {
            rf627_smart->info_by_service_protocol.fact_general_firmwareVer[i] =
                    mpack_node_uint(mpack_node_array_at(mpack_node_map_cstr(root, "fact_general_firmwareVer"), i));
        }
    }

    // Device hardware version.
    if (mpack_node_map_contains_cstr(root, "fact_general_hardwareVer"))
    {
        rf627_smart->info_by_service_protocol.fact_general_hardwareVer =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_hardwareVer"));
    }

    // Size of the measuring range in Z axis in mm.
    if (mpack_node_map_contains_cstr(root, "fact_general_mr"))
    {
        rf627_smart->info_by_service_protocol.fact_general_mr =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_mr"));
    }

    // Device type identifier.
    if (mpack_node_map_contains_cstr(root, "fact_general_productCode"))
    {
        rf627_smart->info_by_service_protocol.fact_general_productCode =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_productCode"));
    }

    // Device serial number.
    if (mpack_node_map_contains_cstr(root, "fact_general_serial"))
    {
        rf627_smart->info_by_service_protocol.fact_general_serial =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_serial"));
    }

    // Start of measuring range in Z axis in mm.
    if (mpack_node_map_contains_cstr(root, "fact_general_smr"))
    {
        rf627_smart->info_by_service_protocol.fact_general_smr =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_smr"));
    }

    // The size along the X axis of the measuring range at the beginning of the range.
    if (mpack_node_map_contains_cstr(root, "fact_general_xsmr"))
    {
        rf627_smart->info_by_service_protocol.fact_general_xsmr =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_xsmr"));
    }

    if (mpack_node_map_contains_cstr(root, "fact_general_xemr"))
    {
        rf627_smart->info_by_service_protocol.fact_general_xemr =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_general_xemr"));
    }

    // The wavelength of the laser, installed in the device.
    if (mpack_node_map_contains_cstr(root, "fact_laser_waveLength"))
    {
        rf627_smart->info_by_service_protocol.fact_laser_waveLength =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_laser_waveLength"));
    }

    // Physical address of the device.
    if (mpack_node_map_contains_cstr(root, "fact_network_macAddr"))
    {
        free(rf627_smart->info_by_service_protocol.fact_network_macAddr);
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "fact_network_macAddr")) + 1;
        rf627_smart->info_by_service_protocol.fact_network_macAddr =
                mpack_node_cstr_alloc(mpack_node_map_cstr(root, "fact_network_macAddr"), type_strlen);
    }

    // User-defined scanner name. It is displayed on the web page of the scanner
    // and can be used to quickly identify scanners.
    if (mpack_node_map_contains_cstr(root, "user_general_deviceName"))
    {
        free(rf627_smart->info_by_service_protocol.user_general_deviceName);
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "user_general_deviceName")) + 1;
        rf627_smart->info_by_service_protocol.user_general_deviceName =
                mpack_node_cstr_alloc(mpack_node_map_cstr(root, "user_general_deviceName"), type_strlen);
    }

    // Turns on and off the automatic negotiation of the Ethernet connection speed.
    if (mpack_node_map_contains_cstr(root, "user_network_autoNeg"))
    {
        rf627_smart->info_by_service_protocol.user_network_autoNeg =
                mpack_node_bool(mpack_node_map_cstr(root, "user_network_autoNeg"));
    }

    // Gateway address.
    if (mpack_node_map_contains_cstr(root, "user_network_gateway"))
    {
        free(rf627_smart->info_by_service_protocol.user_network_gateway);
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "user_network_gateway")) + 1;
        rf627_smart->info_by_service_protocol.user_network_gateway =
                mpack_node_cstr_alloc(mpack_node_map_cstr(root, "user_network_gateway"), type_strlen);
    }

    // Host address.
    if (mpack_node_map_contains_cstr(root, "user_network_hostIP"))
    {
        free(rf627_smart->info_by_service_protocol.user_network_hostIP);
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "user_network_hostIP")) + 1;
        rf627_smart->info_by_service_protocol.user_network_hostIP =
                mpack_node_cstr_alloc(mpack_node_map_cstr(root, "user_network_hostIP"), type_strlen);
    }

    // Turns on and off the automatic negotiation of the Ethernet connection speed.
    if (mpack_node_map_contains_cstr(root, "user_network_hostPort"))
    {
        uint32_t old_hostPort = rf627_smart->info_by_service_protocol.user_network_hostPort;
        rf627_smart->info_by_service_protocol.user_network_hostPort =
                mpack_node_uint(mpack_node_map_cstr(root, "user_network_hostPort"));

        if(old_hostPort != rf627_smart->info_by_service_protocol.user_network_hostPort)
            *update_network = TRUE;
    }

    // The network address of the device
    if (mpack_node_map_contains_cstr(root, "user_network_ip"))
    {
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "user_network_ip")) + 1;
        char* user_network_ip = mpack_node_cstr_alloc(mpack_node_map_cstr(root, "user_network_ip"), type_strlen);
        if (rf_strcmp(rf627_smart->info_by_service_protocol.user_network_ip, user_network_ip) != 0)
            *update_network = TRUE;

        free(rf627_smart->info_by_service_protocol.user_network_ip);
        rf627_smart->info_by_service_protocol.user_network_ip = user_network_ip;
    }

    // Subnet mask for the device
    if (mpack_node_map_contains_cstr(root, "user_network_mask"))
    {
        rfSize type_strlen = mpack_node_strlen(mpack_node_map_cstr(root, "user_network_mask")) + 1;
        char* user_network_mask = mpack_node_cstr_alloc(mpack_node_map_cstr(root, "user_network_mask"), type_strlen);
        if (rf_strcmp(rf627_smart->info_by_service_protocol.user_network_mask, user_network_mask) != 0)
            *update_network = TRUE;

        free(rf627_smart->info_by_service_protocol.user_network_mask);
        rf627_smart->info_by_service_protocol.user_network_mask = user_network_mask;
    }

    // Port number for service protocol.
    if (mpack_node_map_contains_cstr(root, "user_network_servicePort"))
    {
        rf627_smart->info_by_service_protocol.user_network_servicePort =
                mpack_node_uint(mpack_node_map_cstr(root, "user_network_servicePort"));
    }

    // Current Ethernet connection speed. The connection speed is changed by writing
    // to this parameter. In case of auto-negotiation, writing is ignored.
    if (mpack_node_map_contains_cstr(root, "user_network_speed"))
    {
        rf627_smart->info_by_service_protocol.user_network_speed =
                mpack_node_uint(mpack_node_map_cstr(root, "user_network_speed"));
    }

    // Port number to access the Web page.
    if (mpack_node_map_contains_cstr(root, "user_network_webPort"))
    {
        rf627_smart->info_by_service_protocol.user_network_webPort =
                mpack_node_uint(mpack_node_map_cstr(root, "user_network_webPort"));
    }

    // Enabling and disabling the profile stream, transmitted via the UDP protocol
    // (sending to the network address, set by the user_network_hostIP parameter
    // and the port, set by the user_network_hostPort parameter).
    if (mpack_node_map_contains_cstr(root, "user_streams_udpEnabled"))
    {
        rf627_smart->info_by_service_protocol.user_streams_udpEnabled =
                mpack_node_bool(mpack_node_map_cstr(root, "user_streams_udpEnabled"));
    }

    // The format of the transmitted profiles.
    if (mpack_node_map_contains_cstr(root, "user_streams_format"))
    {
        rf627_smart->info_by_service_protocol.user_streams_format =
                mpack_node_uint(mpack_node_map_cstr(root, "user_streams_format"));
    }

    // The maxmim udp packet size.
    if (mpack_node_map_contains_cstr(root, "fact_serviceProtocol_maxPacketSize"))
    {
        rf627_smart->info_by_service_protocol.fact_maxPacketSize =
                mpack_node_uint(mpack_node_map_cstr(root, "fact_serviceProtocol_maxPacketSize"));
    }else
    {
        rf627_smart->info_by_service_protocol.fact_maxPacketSize = 65535;
    }

    mpack_tree_destroy(&tree);

    return TRUE;

}

rf627_smart_hello_info_by_service_protocol* rf627_smart_get_scanner_info_by_service_protocol(rf627_smart_t* scanner)
{
    return &scanner->info_by_service_protocol;
}

parameter_t* rf627_smart_get_parameter(rf627_smart_t* scanner, const rfChar* param_name)
{
    for(rfSize i = 0; i < vector_count(scanner->params_list); i++)
    {
        parameter_t* p = vector_get(scanner->params_list, i);
        if (rf_strcmp(p->base.name, param_name) == 0)
        {
            return p;
        }
    }
    return NULL;
}

rfBool rf627_smart_connect(rf627_smart_t* scanner)
{
    rfUint32 recv_ip_addr;
    rfUint16 recv_port;
    rfInt nret;


    uint32_t host_device_uid = 777;
    uint32_t host_udp_port = 0;
    uint32_t socket_timeout = 100;
    uint32_t max_packet_size = scanner->info_by_service_protocol.fact_maxPacketSize;
    uint32_t max_data_size = 20000000;

    char* config = generate_config_string(
                host_device_uid,
                "0.0.0.0",//scanner->info_by_service_protocol.user_network_hostIP,
                scanner->info_by_service_protocol.user_network_ip,
                host_udp_port,
                scanner->info_by_service_protocol.user_network_servicePort, socket_timeout,
                max_packet_size, max_data_size);

    uint8_t is_init = RF62X_channel_init(&scanner->channel, config);
    free(config);


    if (is_init)
    {
        scanner->m_data_sock =
                network_platform.network_methods.create_udp_socket();
        if (scanner->m_data_sock != (void*)RF_SOCKET_ERROR)
        {
            nret = 1;
            network_platform.network_methods.set_reuseaddr_socket_option(scanner->m_data_sock);

            network_platform.network_methods.set_socket_recv_timeout(
                        scanner->m_data_sock, STREAM_SOCK_RECV_TIMEOUT);
            //recv_addr.sin_family = RF_AF_INET;
            recv_port = scanner->info_by_service_protocol.user_network_hostPort;

            //recv_addr.sin_addr = RF_INADDR_ANY;
            //ip_string_to_uint32(scanner->info_by_service_protocol.user_network_hostIP, &recv_ip_addr);
            recv_ip_addr = 0;

            nret = network_platform.network_methods.socket_bind(
                        scanner->m_data_sock, recv_ip_addr, recv_port);
            if (nret == RF_SOCKET_ERROR)
            {
                network_platform.network_methods.close_socket(scanner->m_data_sock);
                scanner->m_data_sock = NULL;
                return FALSE;
            }
        }
        else
        {
            iostream_platform.trace_error("Create data socket error");
            return FALSE;
        }

        scanner->is_connected = TRUE;
        return TRUE;
    }
    else
    {
        rf627_smart_disconnect(scanner);
    }

    return FALSE;

}
rfBool rf627_smart_disconnect(rf627_smart_t* scanner)
{
    RF62X_channel_cleanup(&scanner->channel);

    if (scanner->m_data_sock != NULL &&
            scanner->m_data_sock != (void*)RF_SOCKET_ERROR)
    {
        network_platform.network_methods.close_socket(scanner->m_data_sock);
        scanner->m_data_sock = NULL;
    }

    scanner->is_connected = FALSE;
    return TRUE;
}

rf627_smart_profile2D_t* rf627_smart_get_profile2D(rf627_smart_t* scanner, rfBool zero_points)
{

    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + 65000;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + 65000;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);

    rfInt nret = network_platform.network_methods.recv_data(
                scanner->m_data_sock, RX, RX_SIZE);
    if(nret > 0)
    {
        rfUint32 profile_header_size =
                rf627_protocol_old_get_size_of_response_profile_header_packet();

        if ((rfUint32)nret > profile_header_size)
        {
            rf627_smart_profile2D_t* profile =
                    memory_platform.rf_calloc(1, sizeof(rf627_smart_profile2D_t));

            rf627_old_stream_msg_t header_from_msg = rf627_protocol_old_unpack_header_msg_from_profile_packet(RX);

            profile->header.data_type = header_from_msg.data_type;
            profile->header.flags = header_from_msg.flags;
            profile->header.device_type = header_from_msg.device_type;
            profile->header.serial_number = header_from_msg.serial_number;
            profile->header.system_time = header_from_msg.system_time;

            profile->header.proto_version_major = header_from_msg.proto_version_major;
            profile->header.proto_version_minor = header_from_msg.proto_version_minor;
            profile->header.hardware_params_offset = header_from_msg.hardware_params_offset;
            profile->header.data_offset = header_from_msg.data_offset;
            profile->header.packet_count = header_from_msg.packet_count;
            profile->header.measure_count = header_from_msg.measure_count;

            profile->header.zmr = header_from_msg.zmr;
            profile->header.xemr = header_from_msg.xemr;
            profile->header.discrete_value = header_from_msg.discrete_value;
            profile->header.license_hash = header_from_msg.license_hash;

            profile->header.exposure_time = header_from_msg.exposure_time;
            profile->header.laser_value = header_from_msg.laser_value;
            profile->header.step_count = header_from_msg.step_count;
            profile->header.dir = header_from_msg.dir;
            profile->header.payload_size = header_from_msg.payload_size;
            profile->header.bytes_per_point = header_from_msg.bytes_per_point;

            if(profile->header.serial_number == scanner->info_by_service_protocol.fact_general_serial)
            {
                rfInt16 x;
                rfUint16 z;

                rfUint32 pt_count;
                switch (profile->header.data_type)
                {
                case DTY_PixelsNormal:
                    pt_count = profile->header.payload_size / profile->header.bytes_per_point;
                    profile->pixels_format.pixels_count = 0;
                    profile->pixels_format.pixels =
                            memory_platform.rf_calloc(pt_count, sizeof (rfUint16));
                    if (profile->header.flags & 0x01){
                        profile->intensity_count = 0;
                        profile->intensity =
                                memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                    }
                    break;
                case DTY_ProfileNormal:
                    pt_count = profile->header.payload_size / profile->header.bytes_per_point;
                    profile->profile_format.points_count = 0;
                    profile->profile_format.points =
                            memory_platform.rf_calloc(pt_count, sizeof (rf627_old_point2D_t));
                    if (profile->header.flags & 0x01){
                        profile->intensity_count = 0;
                        profile->intensity =
                                memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                    }
                    break;
                case DTY_PixelsInterpolated:
                    pt_count = profile->header.payload_size / profile->header.bytes_per_point;
                    profile->pixels_format.pixels_count = 0;
                    profile->pixels_format.pixels =
                            memory_platform.rf_calloc(pt_count, sizeof (rfUint16));
                    if (profile->header.flags & 0x01){
                        profile->intensity_count = 0;
                        profile->intensity =
                                memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                    }
                    break;
                case DTY_ProfileInterpolated:
                    pt_count = profile->header.payload_size / profile->header.bytes_per_point;
                    profile->profile_format.points_count = 0;
                    profile->profile_format.points =
                            memory_platform.rf_calloc(pt_count, sizeof (rf627_old_point2D_t));
                    if (profile->header.flags & 0x01){
                        profile->intensity_count = 0;
                        profile->intensity =
                                memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                    }
                    break;
                }

                for (rfUint32 i=0; i<pt_count; i++)
                {
                    rf627_old_point2D_t pt;
                    switch (profile->header.data_type)
                    {
                    case DTY_ProfileNormal:
                    case DTY_ProfileInterpolated:
                        z = *(rfUint16*)(&RX[profile_header_size + i*4 + 2]);
                        x = *(rfInt16*)(&RX[profile_header_size + i*4]);
                        if (zero_points == FALSE && z > 0)
                        {
                            pt.x = (rfFloat)((rfDouble)(x) * (rfDouble)(profile->header.xemr) /
                                             (rfDouble)(profile->header.discrete_value));
                            pt.z = (rfFloat)((rfDouble)(z) * (rfDouble)(profile->header.zmr) /
                                             (rfDouble)(profile->header.discrete_value));

                            profile->profile_format.points[profile->profile_format.points_count] = pt;
                            profile->profile_format.points_count++;
                            if (profile->header.flags & 0x01)
                            {
                                profile->intensity[profile->intensity_count] = RX[profile_header_size + pt_count*4 + i];
                                profile->intensity_count++;
                            }
                        }else if(zero_points != 0)
                        {
                            pt.x = (rfFloat)((rfDouble)(x) * (rfDouble)(profile->header.xemr) /
                                             (rfDouble)(profile->header.discrete_value));
                            pt.z = (rfFloat)((rfDouble)(z) * (rfDouble)(profile->header.zmr) /
                                             (rfDouble)(profile->header.discrete_value));

                            profile->profile_format.points[profile->profile_format.points_count] = pt;
                            profile->profile_format.points_count++;
                            if (profile->header.flags & 0x01)
                            {
                                profile->intensity[profile->intensity_count] = RX[profile_header_size + pt_count*4 + i];
                                profile->intensity_count++;
                            }
                        }
                        break;
                    case DTY_PixelsNormal:
                    case DTY_PixelsInterpolated:
                        z = *(rfUint16*)(&RX[profile_header_size + i*2]);
                        //pt.x = i;

                        profile->pixels_format.pixels[profile->pixels_format.pixels_count] = z;
                        profile->pixels_format.pixels_count++;
                        if (profile->header.flags & 0x01)
                        {
                            profile->intensity[profile->intensity_count] = RX[profile_header_size + pt_count*4 + i];
                            profile->intensity_count++;
                        }

                        //pt.z = (rfDouble)(z) / (rfDouble)(profile->header.discrete_value);

                        break;
                    }

                }
                //_mx[1].unlock();
                memory_platform.rf_free(RX);
                memory_platform.rf_free(TX);
                return profile;
            }else
            {
                memory_platform.rf_free(profile);
            }
        }
    }
    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);
    return NULL;
}


extern parameter_t* create_parameter_from_type(const rfChar* type);

rfUint8 rf627_smart_set_parameter(rf627_smart_t* scanner, parameter_t* param)
{
    for(rfSize i = 0; i < vector_count(scanner->params_list); i++)
    {
        parameter_t* p = vector_get(scanner->params_list, i);
        if (rf_strcmp(p->base.name, param->base.name) == 0)
        {
            if (rf_strcmp(p->base.type, "string_t") == 0)
            {
                memory_platform.rf_free(p->val_str->value);
                p->val_str->value = memory_platform.rf_calloc(param->base.size, sizeof (rfChar));
                memory_platform.rf_memcpy(
                            (void*)p->val_str->value,
                            param->val_str->value,
                            param->base.size);
                p->base.size = param->base.size;
                p->is_changed = TRUE;
                return TRUE;
            }
            else if (rf_strcmp(p->base.type, "int32_t") == 0)
            {
                p->val_int32->value = param->val_int32->value;
                p->is_changed = TRUE;
                return TRUE;
            }
            else if (rf_strcmp(p->base.type, "int64_t") == 0)
            {
                p->val_int64->value = param->val_int64->value;
                p->is_changed = TRUE;
                return TRUE;
            }
            else if (rf_strcmp(p->base.type, "uint32_t") == 0)
            {
                p->val_uint32->value = param->val_uint32->value;
                p->is_changed = TRUE;
                return TRUE;
            }
            else if (rf_strcmp(p->base.type, "uint64_t") == 0)
            {
                p->val_uint64->value = param->val_uint64->value;
                p->is_changed = TRUE;
                return TRUE;
            }
            else if (rf_strcmp(p->base.type, "float_t") == 0)
            {
                p->val_flt->value = param->val_flt->value;
                p->is_changed = TRUE;
                return TRUE;
            }
            else if (rf_strcmp(p->base.type, "double_t") == 0)
            {
                p->val_dbl->value = param->val_dbl->value;
                p->is_changed = TRUE;
                return TRUE;
            }else if (rf_strcmp(p->base.type, "u32_arr_t") == 0)
            {
                memory_platform.rf_free(p->arr_uint32->value);
                p->arr_uint32->value = memory_platform.rf_calloc(param->base.size, sizeof (uint8_t));
                memory_platform.rf_memcpy(
                            (void*)p->arr_uint32->value,
                            param->arr_uint32->value,
                            param->base.size);
                p->base.size = param->base.size;
                p->is_changed = TRUE;
                return TRUE;
            }

        }
    }
    return FALSE;
}



//
// RF627-Smart (v2.x.x)
// Search Methods
//
rfInt8 rf627_smart_get_hello_callback(
        char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", device_id: %d, "
          "payload size: %d\n", msg->cmd_name, msg->_uid, device_id, data_size);

    // Search among all previously discovered scanners
    for (rfUint32 i = 0; i < vector_count(search_history); i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
        {
            uint32_t serial = scanner->rf627_smart->info_by_service_protocol.fact_general_serial;
            // If the scanner was found again, then update hello-information
            // about and add to current_search_result list, which will be returned
            if (serial == device_id)
            {
                rfBool update_network = FALSE;
                if (!rf627_smart_update_from_hello_msg(data, data_size, scanner->rf627_smart, &update_network))
                {
                    status = FALSE;
                    TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
                          "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
                          msg->cmd_name, msg->_uid, data_size);
                    return status;
                }
                if (update_network && scanner->rf627_smart->is_connected)
                {
                    rf627_smart_disconnect(scanner->rf627_smart);
                    rf627_smart_connect(scanner->rf627_smart);
                }
                rfBool _existing = FALSE;
                for (rfUint32 ii = 0; ii < vector_count(current_search_result); ii++)
                {
                    scanner_base_t* _scanner = (scanner_base_t*)vector_get(current_search_result, ii);
                    if(_scanner->type == kRF627_SMART)
                    {
                        uint32_t _serial = _scanner->rf627_smart->info_by_service_protocol.fact_general_serial;
                        // If the scanner was found again, then update hello-information
                        // about and add to current_search_result list, which will be returned
                        if (_serial == device_id) {
                            _existing = TRUE;
                        }
                    }
                }
                if (!_existing)
                    vector_add(current_search_result, vector_get(search_history,i));
                existing = TRUE;
                status = TRUE;
            }
        }
    }

    // If this scanner was discovered for the first time, then also add it
    // to the search_result list
    if (!existing)
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "Found scanner %d\n", device_id);

        scanner_base_t* rf627 =
                memory_platform.rf_calloc(1, sizeof(scanner_base_t));

        rf627->type = kRF627_SMART;
        rf627->rf627_smart = rf627_smart_create_from_hello_msg(data, data_size);
        if (rf627->rf627_smart == NULL)
        {
            TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
                  "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
                  msg->cmd_name, msg->_uid, data_size);
            free(rf627);
        }else
        {
            vector_add(search_history, rf627);
            vector_add(current_search_result,
                       vector_get(search_history, vector_count(search_history)-1));

            status = TRUE;
        }
    }

    if (status)
    {
        // Answer:
        // {
        //    count: uint32_t
        // }
        typedef struct
        {
            uint32_t count;
        }answer;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }
        ((answer*)msg->result)->count =
                (uint32_t)vector_count(current_search_result);
    }

    return status;

}
rfInt8 rf627_smart_get_hello_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_get_hello_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    count: uint32_t
        // }
        typedef struct
        {
            uint32_t count;
        }answer;

        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfUint8 rf627_smart_search_by_service_protocol(vector_t *scanner_list, rfUint32 ip_addr, rfUint32 timeout)
{
    if (search_history == NULL)
    {
        search_history = (vector_t*)calloc(1, sizeof (vector_t));
        //Initialization vector
        vector_init(&search_history);
    }

    // Если изменился указатель на старый результат поиска, значит поиск был
    // запущен повторно. Поэтому неоходимо очистить память, выделенную во
    // время предыдущего поиска.
    if (current_search_result != scanner_list && current_search_result != NULL)
    {
        while (vector_count(current_search_result) > 0) {
            vector_delete(current_search_result, vector_count(current_search_result)-1);
        }
        free (current_search_result); current_search_result = NULL;
    }
    current_search_result = scanner_list;

    rfUint8 scanner_count = 0;
    {
        // Init RF62X-Protocol channel
        rfUint32 host_device_uid    = 777;
        // Set host_ip_addr from ip_addr
        char* host_ip_addr          = NULL;
        uint32_to_ip_string(ip_addr, &host_ip_addr);
        // Set dst_ip_addr modify ip_addr (*.*.*.255)
        char* dst_ip_addr           = NULL;
        uint32_to_ip_string(((rfUint32)(ip_addr) | 0xFF), &dst_ip_addr);
        // No fixed port (automatically assigned by the operating system)
        rfUint32 host_udp_port = 0;
        // Fixed service scanner port.
        rfUint32 dst_udp_port = 50011;
        // Other parameters
        rfUint32 socket_timeout = 100;
        rfUint32 max_packet_size = 65535;
        rfUint32 max_data_size = 20000000;

        // generate config string for RF62X-Protocol
        char* config = generate_config_string(
                    host_device_uid, host_ip_addr, dst_ip_addr,
                    host_udp_port, dst_udp_port, socket_timeout,
                    max_packet_size, max_data_size);

        RF62X_channel_t channel;
        rfBool is_inited = RF62X_channel_init(&channel, config);

        free(host_ip_addr); free(dst_ip_addr); free(config);

        if (is_inited == TRUE)
        {
            // cmd_name - this is logical port/path where data will be send
            char* cmd_name                      = "GET_HELLO";
            // payload - this is the data to be sent and their size
            char* payload                       = NULL;
            uint32_t payload_size               = 0;
            // data_type - this is the type of packaging of the sent data
            char* data_type                     = "blob";  // mpack, json, blob..
            uint8_t is_check_crc                = FALSE;   // check crc disabled
            uint8_t is_confirmation             = FALSE;   // confirmation disabled
            uint8_t is_one_answ                 = FALSE;   // wait all answers
            uint32_t waiting_time               = timeout; // ms
            uint32_t resends                    = is_confirmation ? 3 : 0;
            // callbacks for request
            RF62X_answ_callback answ_clb        = rf627_smart_get_hello_callback;
            RF62X_timeout_callback timeout_clb  = rf627_smart_get_hello_timeout_callback;
            RF62X_free_callback free_clb        = rf627_smart_get_hello_free_result_callback;

            // Create request message
            RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                                     is_check_crc, is_confirmation, is_one_answ,
                                                     waiting_time, resends,
                                                     answ_clb, timeout_clb, free_clb);

            // Send request msg
            if (RF62X_channel_send_msg(&channel, msg))
            {
                TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

                // try to find answer to rqst
                pthread_mutex_lock(msg->result_mutex);
                void* result = RF62X_find_result_to_rqst_msg(&channel, msg, waiting_time);
                if (result != NULL)
                {
                    // Answer:
                    // {
                    //    count: uint32_t
                    // }
                    typedef struct
                    {
                        uint32_t count;
                    }answer;

                    scanner_count = ((answer*)result)->count;
                }
                pthread_mutex_unlock(msg->result_mutex);
            }
            else
            {
                TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
            }

            // Cleanup msg
            RF62X_cleanup_msg(msg);
            free(msg); msg = NULL;
        }else
        {
            TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "Smart channel not initialized: %s", config);
        }

        RF62X_channel_cleanup(&channel);
    }

    {
        // Init RF62X-Protocol channel
        rfUint32 host_device_uid    = 777;
        // Set host_ip_addr from ip_addr
        char* host_ip_addr          = NULL;
        uint32_to_ip_string(ip_addr, &host_ip_addr);
        // Set dst_ip_addr modify ip_addr (*.*.*.255)
        char* dst_ip_addr           = NULL;
        uint32_to_ip_string(((rfUint32)(ip_addr) | 0xFFFFFFFF), &dst_ip_addr);
        // No fixed port (automatically assigned by the operating system)
        rfUint32 host_udp_port = 50011;
        // Fixed service scanner port.
        rfUint32 dst_udp_port = 50011;
        // Other parameters
        rfUint32 socket_timeout = 100;
        rfUint32 max_packet_size = 65535;
        rfUint32 max_data_size = 20000000;

        // generate config string for RF62X-Protocol
        char* config = generate_config_string(
                    host_device_uid, host_ip_addr, dst_ip_addr,
                    host_udp_port, dst_udp_port, socket_timeout,
                    max_packet_size, max_data_size);

        RF62X_channel_t channel;
        rfBool is_inited = RF62X_channel_init(&channel, config);

        free(host_ip_addr); free(dst_ip_addr); free(config);

        if (is_inited == TRUE)
        {
            // cmd_name - this is logical port/path where data will be send
            char* cmd_name                      = "GET_HELLO";
            // payload - this is the data to be sent and their size
            char* payload                       = NULL;
            uint32_t payload_size               = 0;
            // data_type - this is the type of packaging of the sent data
            char* data_type                     = "blob";  // mpack, json, blob..
            uint8_t is_check_crc                = FALSE;   // check crc disabled
            uint8_t is_confirmation             = FALSE;   // confirmation disabled
            uint8_t is_one_answ                 = FALSE;   // wait all answers
            uint32_t waiting_time               = timeout; // ms
            uint32_t resends                    = is_confirmation ? 3 : 0;
            // callbacks for request
            RF62X_answ_callback answ_clb        = rf627_smart_get_hello_callback;
            RF62X_timeout_callback timeout_clb  = rf627_smart_get_hello_timeout_callback;
            RF62X_free_callback free_clb        = rf627_smart_get_hello_free_result_callback;

            // Create request message
            RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                                     is_check_crc, is_confirmation, is_one_answ,
                                                     waiting_time, resends,
                                                     answ_clb, timeout_clb, free_clb);

            // Send request msg
            if (RF62X_channel_send_msg(&channel, msg))
            {
                TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

                // try to find answer to rqst
                pthread_mutex_lock(msg->result_mutex);
                void* result = RF62X_find_result_to_rqst_msg(&channel, msg, waiting_time);
                if (result != NULL)
                {
                    // Answer:
                    // {
                    //    count: uint32_t
                    // }
                    typedef struct
                    {
                        uint32_t count;
                    }answer;

                    scanner_count = ((answer*)result)->count;
                }
                pthread_mutex_unlock(msg->result_mutex);
            }
            else
            {
                TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
            }

            // Cleanup msg
            RF62X_cleanup_msg(msg);
            free(msg); msg = NULL;
        }else
        {
            TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "Smart channel not initialized: %s", config);
        }

        RF62X_channel_cleanup(&channel);
    }
    return scanner_count;
}


rfUint8 rf627_smart_search_by_ip_by_service_protocol(
        vector_t* scanner_list, rfUint32 ip_host, rfChar* ip_src, rfUint32 timeout)
{
    if (search_history == NULL)
    {
        search_history = (vector_t*)calloc(1, sizeof (vector_t));
        //Initialization vector
        vector_init(&search_history);
    }

    // Если изменился указатель на старый результат поиска, значит поиск был
    // запущен повторно. Поэтому неоходимо очистить память, выделенную во
    // время предыдущего поиска.
    if (current_search_result != scanner_list && current_search_result != NULL)
    {
        while (vector_count(current_search_result) > 0) {
            vector_delete(current_search_result, vector_count(current_search_result)-1);
        }
        free (current_search_result); current_search_result = NULL;
    }
    current_search_result = scanner_list;

    rfUint8 scanner_count = 0;
    {
        // Init RF62X-Protocol channel
        rfUint32 host_device_uid    = 777;
        // Set host_ip_addr from ip_addr
        char* host_ip_addr          = NULL;
        uint32_to_ip_string(ip_host, &host_ip_addr);
        // Set dst_ip_addr modify ip_addr (*.*.*.255)
        char* dst_ip_addr           = ip_src;
        // No fixed port (automatically assigned by the operating system)
        rfUint32 host_udp_port = 0;
        // Fixed service scanner port.
        rfUint32 dst_udp_port = 50011;
        // Other parameters
        rfUint32 socket_timeout = 100;
        rfUint32 max_packet_size = 65535;
        rfUint32 max_data_size = 20000000;

        // generate config string for RF62X-Protocol
        char* config = generate_config_string(
                    host_device_uid, host_ip_addr, dst_ip_addr,
                    host_udp_port, dst_udp_port, socket_timeout,
                    max_packet_size, max_data_size);

        RF62X_channel_t channel;
        rfBool is_inited = RF62X_channel_init(&channel, config);

        free(host_ip_addr); free(config);

        if (is_inited == TRUE)
        {
            // cmd_name - this is logical port/path where data will be send
            char* cmd_name                      = "GET_HELLO";
            // payload - this is the data to be sent and their size
            char* payload                       = NULL;
            uint32_t payload_size               = 0;
            // data_type - this is the type of packaging of the sent data
            char* data_type                     = "blob";  // mpack, json, blob..
            uint8_t is_check_crc                = FALSE;   // check crc disabled
            uint8_t is_confirmation             = FALSE;   // confirmation disabled
            uint8_t is_one_answ                 = TRUE;   // wait all answers
            uint32_t waiting_time               = timeout; // ms
            uint32_t resends                    = is_confirmation ? 3 : 0;
            // callbacks for request
            RF62X_answ_callback answ_clb        = rf627_smart_get_hello_callback;
            RF62X_timeout_callback timeout_clb  = rf627_smart_get_hello_timeout_callback;
            RF62X_free_callback free_clb        = rf627_smart_get_hello_free_result_callback;

            // Create request message
            RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                                     is_check_crc, is_confirmation, is_one_answ,
                                                     waiting_time, resends,
                                                     answ_clb, timeout_clb, free_clb);

            // Send request msg
            if (RF62X_channel_send_msg(&channel, msg))
            {
                TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

                // try to find answer to rqst
                pthread_mutex_lock(msg->result_mutex);
                void* result = RF62X_find_result_to_rqst_msg(&channel, msg, waiting_time);
                if (result != NULL)
                {
                    // Answer:
                    // {
                    //    count: uint32_t
                    // }
                    typedef struct
                    {
                        uint32_t count;
                    }answer;

                    scanner_count = ((answer*)result)->count;
                }
                pthread_mutex_unlock(msg->result_mutex);
            }
            else
            {
                TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
            }

            // Cleanup msg
            RF62X_cleanup_msg(msg);
            free(msg); msg = NULL;
        }else
        {
            TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "Smart channel not initialized: %s", config);
        }

        RF62X_channel_cleanup(&channel);
    }

    return scanner_count;
}

//
// RF627-Smart (v2.x.x)
// Profile2D Software Request Methods
//
rfInt8 rf627_smart_send_profile2D_request_callback(
        char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        mpack_node_t result_data = mpack_node_map_cstr(root, "result");
        uint32_t result_size = mpack_node_strlen(result_data) + 1;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->result =
                mpack_node_cstr_alloc(result_data, result_size);

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_send_profile2D_request_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_send_profile2D_request_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_send_profile2D_request_to_scanner(rf627_smart_t* scanner, rfUint32 count)
{
    // Create payload
    mpack_writer_t writer;
    rfChar* data = NULL; //< A growing array for msg.
    rfSize data_size = 0; //< Number of msg bytes.
    mpack_writer_init_growable(&writer, &data, &data_size);


    // Payload:
    // {
    //    count: Number (uint32_t)
    // }
    mpack_start_map(&writer, 1);
    {
        // Number of measurements
        mpack_write_cstr(&writer, "count");
        mpack_write_uint(&writer, count);
    }mpack_finish_map(&writer);

    // finish writing
    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");
        return FALSE;
    }

    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "CAPTURE_PROFILE";
    // payload - this is the data to be sent and their size
    char* payload                       = data;
    uint32_t payload_size               = (uint32_t)data_size;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "mpack"; // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = 1000;    // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_send_profile2D_request_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_send_profile2D_request_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_send_profile2D_request_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);
    // free memory of payload
    free(payload);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: String (*)
            // }
            // * result: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            typedef struct
            {
                char* result;
            }answer;

            if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0)
                status = TRUE;
            else
                status = FALSE;

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ",((answer*)result)->result);

        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Check Connection Methods
//
rfInt8 rf627_smart_check_connection_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    for (rfUint32 i = 0; i < vector_count(search_history); i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
            {
                existing = TRUE;
                rfBool update_network = FALSE;
                if (!rf627_smart_update_from_hello_msg(data, data_size, scanner->rf627_smart, &update_network))
                {
                    status = FALSE;
                    TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
                          "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
                          msg->cmd_name, msg->_uid, data_size);
                    return status;
                }
                if (update_network)
                {
                    //rf627_smart_disconnect(scanner->rf627_smart);
                    //rf627_smart_connect(scanner->rf627_smart);
                }
            }
    }

    // If scanner exist
    if (existing)
    {

        // Answer:
        // {
        //    device_id: uint32_t
        // }
        typedef struct
        {
            uint32_t device_id;
        }answer;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }
        ((answer*)msg->result)->device_id = device_id;

        status = TRUE;
    }

    return TRUE;
}
rfInt8 rf627_smart_check_connection_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_check_connection_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    device_id: uint32_t
        // }
        typedef struct
        {
            uint32_t device_id;
        }answer;

        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_check_connection_by_service_protocol(rf627_smart_t* scanner, rfUint32 timeout)
{
    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "GET_HELLO";
    // payload - this is the data to be sent and their size
    char* payload                       = NULL;
    uint32_t payload_size               = 0;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_check_connection_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_check_connection_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_check_connection_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    uint32_t device_id = 0;

    // Send request msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    device_id: uint32_t
            // }
            typedef struct
            {
                uint32_t device_id;
            }answer;

            device_id = ((answer*)result)->device_id;
        }
        else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    // Cleanup msg
    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return device_id == scanner->info_by_service_protocol.fact_general_serial;
}


//
// RF627-Smart (v2.x.x)
// Read Params Method
//
rfInt8 rf627_smart_read_params_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    scanner_base_t* scanner = NULL;
    for (rfUint32 i = 0; i < vector_count(search_history); i++)
    {
        scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
        {
            uint32_t serial = scanner->rf627_smart->info_by_service_protocol.fact_general_serial;
            if (serial == device_id)
            {
                existing = TRUE;
                break;
            }
        }
    }


    if (existing)
    {
        // Get params
        mpack_tree_t tree;
        mpack_tree_init_data(&tree, (const char*)data, data_size);
        mpack_tree_parse(&tree);
        if (mpack_tree_error(&tree) != mpack_ok)
        {
            status = FALSE;
            mpack_tree_destroy(&tree);
            return status;
        }
        mpack_node_t root = mpack_tree_root(&tree);

        mpack_node_t factory = mpack_node_map_cstr(root, "factory");
        uint32_t factory_arr_size = (uint32_t)mpack_node_array_length(factory);

        for (uint32_t i = 0; i < factory_arr_size; i++)
        {
            parameter_t* p = NULL;
            // type
            if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "type"))
            {
                char* test = (char*)mpack_node_str(mpack_node_map_cstr(mpack_node_array_at(factory, i), "type"));
                p = (parameter_t*)create_parameter_from_type(test);
                // TODO is_changed как использовать
                p->is_changed = FALSE;
            }

            if (p == NULL)
            {
                continue;
            }


            // access
            if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "access"))
            {
                size_t param_strlen = mpack_node_strlen(mpack_node_map_cstr(mpack_node_array_at(factory, i), "access")) + 1;
                p->base.access = mpack_node_cstr_alloc(mpack_node_map_cstr(mpack_node_array_at(factory, i), "access"), param_strlen);
            }


            if(rf_strcmp("uint32_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {
                    p->val_uint32->defValue =
                            mpack_node_u32(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));

                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {
                    p->val_uint32->value =
                            mpack_node_u32(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));

                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->val_uint32->max = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->val_uint32->min = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->val_uint32->step = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
                // valuesEnum
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "valuesEnum"))
                {

                    p->val_uint32->enumValues = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
                    p->val_uint32->enumValues->recCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "valuesEnum"));
                    p->val_uint32->enumValues->rec = memory_platform.rf_calloc(p->val_uint32->enumValues->recCount, sizeof(enumRec_t));
                    for (rfUint32 ii = 0; ii < p->val_uint32->enumValues->recCount; ii++)
                    {
                        p->val_uint32->enumValues->rec[ii].value =
                                mpack_node_i32(
                                    mpack_node_map_cstr(
                                        mpack_node_array_at(
                                            mpack_node_map_cstr(
                                                mpack_node_array_at(
                                                    factory, i), "valuesEnum"), ii), "value"));
                        uint32_t key_strlen =
                                (rfUint32)mpack_node_strlen(
                                    mpack_node_map_cstr(
                                        mpack_node_array_at(
                                            mpack_node_map_cstr(
                                                mpack_node_array_at(
                                                    factory, i), "valuesEnum"), ii), "key")) + 1;
                        p->val_uint32->enumValues->rec[ii].key =
                                mpack_node_cstr_alloc(
                                    mpack_node_map_cstr(
                                        mpack_node_array_at(
                                            mpack_node_map_cstr(
                                                mpack_node_array_at(
                                                    factory, i), "valuesEnum"), ii), "key"), key_strlen);


                        rfUint32 label_strlen =
                                (rfUint32)mpack_node_strlen(
                                    mpack_node_map_cstr(
                                        mpack_node_array_at(
                                            mpack_node_map_cstr(
                                                mpack_node_array_at(
                                                    factory, i), "valuesEnum"), ii), "label")) + 1;
                        p->val_uint32->enumValues->rec[ii].label =
                                mpack_node_cstr_alloc(
                                    mpack_node_map_cstr(
                                        mpack_node_array_at(
                                            mpack_node_map_cstr(
                                                mpack_node_array_at(
                                                    factory, i), "valuesEnum"), ii), "label"), label_strlen);
                    }
                }
            }else if(rf_strcmp("uint64_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {
                    p->val_uint64->defValue =
                            mpack_node_u64(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {
                    p->val_uint64->value =
                            mpack_node_u64(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->val_uint64->max = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->val_uint64->min = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->val_uint64->step = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
            }else if(rf_strcmp("int32_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {
                    p->val_int32->defValue =
                            mpack_node_i32(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {
                    p->val_int32->value =
                            mpack_node_i32(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->val_int32->max = mpack_node_i32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->val_int32->min = mpack_node_i32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->val_int32->step = mpack_node_i32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
            }else if(rf_strcmp("int64_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {
                    p->val_int64->defValue =
                            mpack_node_i64(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {
                    p->val_int64->value =
                            mpack_node_i64(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->val_int64->max = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->val_int64->min = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->val_int64->step = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
            }else if(rf_strcmp("float_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {
                    p->val_flt->defValue =
                            mpack_node_float(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {
                    p->val_flt->value =
                            mpack_node_float(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->val_flt->max = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->val_flt->min = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->val_flt->step = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
            }else if(rf_strcmp("double_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {

                    p->val_dbl->defValue =
                            mpack_node_double(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {

                    p->val_dbl->value =
                            mpack_node_double(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->val_dbl->max = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->val_dbl->min = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->val_dbl->step = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
            }else if(rf_strcmp("u32_arr_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {

                    p->arr_uint32->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));
                    p->arr_uint32->defValue = memory_platform.rf_calloc(p->arr_uint32->defCount, sizeof (uint32_t));
                    for (rfUint32 ii = 0; ii < p->arr_uint32->defCount; ii++)
                        p->arr_uint32->defValue[ii] =
                                mpack_node_u32(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {

                    p->arr_uint32->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));
                    p->arr_uint32->value = memory_platform.rf_calloc(p->arr_uint32->count, sizeof (uint32_t));
                    for (rfUint32 ii = 0; ii < p->arr_uint32->count; ii++)
                        p->arr_uint32->value[ii] =
                                mpack_node_u32(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->arr_uint32->max = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->arr_uint32->min = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "maxCount"))
                {
                    p->arr_uint32->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->arr_uint32->step = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
            }else if(rf_strcmp("u64_arr_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {

                    p->arr_uint64->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));
                    p->arr_uint64->defValue = memory_platform.rf_calloc(p->arr_uint64->defCount, sizeof (uint64_t));
                    for (rfUint32 ii = 0; ii < p->arr_uint64->defCount; ii++)
                        p->arr_uint64->defValue[ii] =
                                mpack_node_u64(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {

                    p->arr_uint64->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));
                    p->arr_uint64->value = memory_platform.rf_calloc(p->arr_uint64->count, sizeof (uint64_t));
                    for (rfUint32 ii = 0; ii < p->arr_uint64->count; ii++)
                        p->arr_uint64->value[ii] =
                                mpack_node_u64(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->arr_uint64->max = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->arr_uint64->min = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "maxCount"))
                {
                    p->arr_uint64->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->arr_uint64->step = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
            }else if(rf_strcmp("i32_arr_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {

                    p->arr_int32->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));
                    p->arr_int32->defValue = memory_platform.rf_calloc(p->arr_int32->defCount, sizeof (int32_t));
                    for (rfUint32 ii = 0; ii < p->arr_int32->defCount; ii++)
                        p->arr_int32->defValue[ii] =
                                mpack_node_i32(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {

                    p->arr_int32->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));
                    p->arr_int32->value = memory_platform.rf_calloc(p->arr_int32->count, sizeof (int32_t));
                    for (rfUint32 ii = 0; ii < p->arr_int32->count; ii++)
                        p->arr_int32->value[ii] =
                                mpack_node_i32(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->arr_int32->max = mpack_node_i32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->arr_int32->min = mpack_node_i32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "maxCount"))
                {
                    p->arr_int32->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->arr_int32->step = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
            }else if(rf_strcmp("i64_arr_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {

                    p->arr_int64->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));
                    p->arr_int64->defValue = memory_platform.rf_calloc(p->arr_int64->defCount, sizeof (int64_t));
                    for (rfUint32 ii = 0; ii < p->arr_int64->defCount; ii++)
                        p->arr_int64->defValue[ii] =
                                mpack_node_i64(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {

                    p->arr_int64->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));
                    p->arr_int64->value = memory_platform.rf_calloc(p->arr_int64->count, sizeof (int64_t));
                    for (rfUint32 ii = 0; ii < p->arr_int64->count; ii++)
                        p->arr_int64->value[ii] =
                                mpack_node_i64(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->arr_int64->max = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->arr_int64->min = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "maxCount"))
                {
                    p->arr_int64->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->arr_int64->step = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
            }else if(rf_strcmp("flt_array_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {

                    p->arr_flt->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));
                    p->arr_flt->defValue = memory_platform.rf_calloc(p->arr_flt->defCount, sizeof (float));
                    for (rfUint32 ii = 0; ii < p->arr_flt->defCount; ii++)
                        p->arr_flt->defValue[ii] =
                                mpack_node_float(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {

                    p->arr_flt->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));
                    p->arr_flt->value = memory_platform.rf_calloc(p->arr_flt->count, sizeof (float));
                    for (rfUint32 ii = 0; ii < p->arr_flt->count; ii++)
                        p->arr_flt->value[ii] =
                                mpack_node_float(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->arr_flt->max = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->arr_flt->min = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "maxCount"))
                {
                    p->arr_flt->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->arr_flt->step = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
            }else if(rf_strcmp("dbl_array_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {

                    p->arr_dbl->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "defaultValue"));
                    p->arr_dbl->defValue = memory_platform.rf_calloc(p->arr_dbl->defCount, sizeof (double));
                    for (rfUint32 ii = 0; ii < p->arr_dbl->defCount; ii++)
                        p->arr_dbl->defValue[ii] =
                                mpack_node_double(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {

                    p->arr_dbl->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        factory, i), "value"));
                    p->arr_dbl->value = memory_platform.rf_calloc(p->arr_dbl->count, sizeof (double));
                    for (rfUint32 ii = 0; ii < p->arr_dbl->count; ii++)
                        p->arr_dbl->value[ii] =
                                mpack_node_double(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                factory, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "max"))
                {
                    p->arr_dbl->max = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(factory, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "min"))
                {
                    p->arr_dbl->min = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(factory, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "maxCount"))
                {
                    p->arr_dbl->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "step"))
                {
                    p->arr_dbl->step = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(factory, i), "step"));
                }
            }else if(rf_strcmp("string_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "defaultValue"))
                {

                    size_t param_strlen = mpack_node_strlen(mpack_node_map_cstr(mpack_node_array_at(factory, i), "defaultValue")) + 1;
                    p->val_str->defValue = mpack_node_cstr_alloc(mpack_node_map_cstr(mpack_node_array_at(factory, i), "defaultValue"), param_strlen);
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "value"))
                {

                    size_t param_strlen = mpack_node_strlen(mpack_node_map_cstr(mpack_node_array_at(factory, i), "value")) + 1;
                    p->val_str->value = mpack_node_cstr_alloc(mpack_node_map_cstr(mpack_node_array_at(factory, i), "value"), param_strlen);
                }
                // maxLen
                if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "maxLen"))
                {
                    p->val_str->maxLen = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(factory, i), "maxLen"));
                }
            }



            // index
            if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "index"))
            {
                p->base.index = mpack_node_uint(mpack_node_map_cstr(mpack_node_array_at(factory, i), "index"));
            }

            // name
            if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "name"))
            {
                size_t param_strlen = mpack_node_strlen(mpack_node_map_cstr(mpack_node_array_at(factory, i), "name")) + 1;
                p->base.name = mpack_node_cstr_alloc(mpack_node_map_cstr(mpack_node_array_at(factory, i), "name"), param_strlen);
            }

            // offset
            if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "offset"))
            {
                p->base.offset = mpack_node_uint(mpack_node_map_cstr(mpack_node_array_at(factory, i), "offset"));
            }

            // size
            if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "size"))
            {
                p->base.size = mpack_node_uint(mpack_node_map_cstr(mpack_node_array_at(factory, i), "size"));
            }

            // units
            if (mpack_node_map_contains_cstr(mpack_node_array_at(factory, i), "units"))
            {
                size_t param_strlen = mpack_node_strlen(mpack_node_map_cstr(mpack_node_array_at(factory, i), "units")) + 1;
                p->base.units = mpack_node_cstr_alloc(mpack_node_map_cstr(mpack_node_array_at(factory, i), "units"), param_strlen);
            }else
            {
                p->base.units = "";
            }

            vector_add(scanner->rf627_smart->params_list, p);
        }

        mpack_node_t user = mpack_node_map_cstr(root, "user");
        rfUint32 user_arr_size = (rfUint32)mpack_node_array_length(user);

        for (rfUint32 i = 0; i < user_arr_size; i++)
        {
            parameter_t* p = NULL;
            // type
            if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "type"))
            {
                char* test = (char*)mpack_node_str(mpack_node_map_cstr(mpack_node_array_at(user, i), "type"));
                p = (parameter_t*)create_parameter_from_type(test);
                // TODO is_changed как использовать
                p->is_changed = FALSE;
            }

            if (p == NULL)
            {
                continue;
            }


            // access
            if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "access"))
            {
                size_t param_strlen = mpack_node_strlen(mpack_node_map_cstr(mpack_node_array_at(user, i), "access")) + 1;
                p->base.access = mpack_node_cstr_alloc(mpack_node_map_cstr(mpack_node_array_at(user, i), "access"), param_strlen);
            }

            if(rf_strcmp("uint32_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {
                    p->val_uint32->defValue =
                            mpack_node_u32(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));

                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {
                    p->val_uint32->value =
                            mpack_node_u32(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));

                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->val_uint32->max = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->val_uint32->min = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->val_uint32->step = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }

                // valuesEnum
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "valuesEnum"))
                {

                    p->val_uint32->enumValues = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
                    p->val_uint32->enumValues->recCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "valuesEnum"));
                    p->val_uint32->enumValues->rec = memory_platform.rf_calloc(p->val_uint32->enumValues->recCount, sizeof(enumRec_t));
                    for (rfUint32 ii = 0; ii < p->val_uint32->enumValues->recCount; ii++)
                    {
                        p->val_uint32->enumValues->rec[ii].value =
                                mpack_node_i32(
                                    mpack_node_map_cstr(
                                        mpack_node_array_at(
                                            mpack_node_map_cstr(
                                                mpack_node_array_at(
                                                    user, i), "valuesEnum"), ii), "value"));
                        rfUint32 key_strlen =
                                (rfUint32)mpack_node_strlen(
                                    mpack_node_map_cstr(
                                        mpack_node_array_at(
                                            mpack_node_map_cstr(
                                                mpack_node_array_at(
                                                    user, i), "valuesEnum"), ii), "key")) + 1;
                        p->val_uint32->enumValues->rec[ii].key =
                                mpack_node_cstr_alloc(
                                    mpack_node_map_cstr(
                                        mpack_node_array_at(
                                            mpack_node_map_cstr(
                                                mpack_node_array_at(
                                                    user, i), "valuesEnum"), ii), "key"), key_strlen);


                        rfUint32 label_strlen =
                                (rfUint32)mpack_node_strlen(
                                    mpack_node_map_cstr(
                                        mpack_node_array_at(
                                            mpack_node_map_cstr(
                                                mpack_node_array_at(
                                                    user, i), "valuesEnum"), ii), "label")) + 1;
                        p->val_uint32->enumValues->rec[ii].label =
                                mpack_node_cstr_alloc(
                                    mpack_node_map_cstr(
                                        mpack_node_array_at(
                                            mpack_node_map_cstr(
                                                mpack_node_array_at(
                                                    user, i), "valuesEnum"), ii), "label"), label_strlen);
                    }
                }

            }else if(rf_strcmp("uint64_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {
                    p->val_uint64->defValue =
                            mpack_node_u64(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {
                    p->val_uint64->value =
                            mpack_node_u64(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->val_uint64->max = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->val_uint64->min = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->val_uint64->step = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }
            }else if(rf_strcmp("int32_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {
                    p->val_int32->defValue =
                            mpack_node_i32(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {
                    p->val_int32->value =
                            mpack_node_i32(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->val_int32->max = mpack_node_i32(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->val_int32->min = mpack_node_i32(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->val_int32->step = mpack_node_i32(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }
            }else if(rf_strcmp("int64_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {
                    p->val_int64->defValue =
                            mpack_node_i64(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {
                    p->val_int64->value =
                            mpack_node_i64(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->val_int64->max = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->val_int64->min = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->val_int64->step = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }
            }else if(rf_strcmp("float_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {
                    p->val_flt->defValue =
                            mpack_node_float(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {
                    p->val_flt->value =
                            mpack_node_float(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->val_flt->max = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->val_flt->min = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->val_flt->step = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }
            }else if(rf_strcmp("double_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {

                    p->val_dbl->defValue =
                            mpack_node_double(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {

                    p->val_dbl->value =
                            mpack_node_double(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->val_dbl->max = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->val_dbl->min = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->val_dbl->step = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }
            }else if(rf_strcmp("u32_arr_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {

                    p->arr_uint32->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));
                    p->arr_uint32->defValue = memory_platform.rf_calloc(p->arr_uint32->defCount, sizeof (uint32_t));
                    for (rfUint32 ii = 0; ii < p->arr_uint32->defCount; ii++)
                        p->arr_uint32->defValue[ii] =
                                mpack_node_u32(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {

                    p->arr_uint32->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));
                    p->arr_uint32->value = memory_platform.rf_calloc(p->arr_uint32->count, sizeof (uint32_t));
                    for (rfUint32 ii = 0; ii < p->arr_uint32->count; ii++)
                        p->arr_uint32->value[ii] =
                                mpack_node_u32(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->arr_uint32->max = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->arr_uint32->min = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "maxCount"))
                {
                    p->arr_uint32->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->arr_uint32->step = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }
            }else if(rf_strcmp("u64_arr_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {

                    p->arr_uint64->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));
                    p->arr_uint64->defValue = memory_platform.rf_calloc(p->arr_uint64->defCount, sizeof (uint64_t));
                    for (rfUint32 ii = 0; ii < p->arr_uint64->defCount; ii++)
                        p->arr_uint64->defValue[ii] =
                                mpack_node_u64(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {

                    p->arr_uint64->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));
                    p->arr_uint64->value = memory_platform.rf_calloc(p->arr_uint64->count, sizeof (uint64_t));
                    for (rfUint32 ii = 0; ii < p->arr_uint64->count; ii++)
                        p->arr_uint64->value[ii] =
                                mpack_node_u64(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->arr_uint64->max = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->arr_uint64->min = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "maxCount"))
                {
                    p->arr_uint64->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->arr_uint64->step = mpack_node_u64(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }
            }else if(rf_strcmp("i32_arr_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {

                    p->arr_int32->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));
                    p->arr_int32->defValue = memory_platform.rf_calloc(p->arr_int32->defCount, sizeof (int32_t));
                    for (rfUint32 ii = 0; ii < p->arr_int32->defCount; ii++)
                        p->arr_int32->defValue[ii] =
                                mpack_node_i32(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {

                    p->arr_int32->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));
                    p->arr_int32->value = memory_platform.rf_calloc(p->arr_int32->count, sizeof (int32_t));
                    for (rfUint32 ii = 0; ii < p->arr_int32->count; ii++)
                        p->arr_int32->value[ii] =
                                mpack_node_i32(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->arr_int32->max = mpack_node_i32(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->arr_int32->min = mpack_node_i32(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "maxCount"))
                {
                    p->arr_int32->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->arr_int32->step = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }
            }else if(rf_strcmp("i64_arr_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {

                    p->arr_int64->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));
                    p->arr_int64->defValue = memory_platform.rf_calloc(p->arr_int64->defCount, sizeof (int64_t));
                    for (rfUint32 ii = 0; ii < p->arr_int64->defCount; ii++)
                        p->arr_int64->defValue[ii] =
                                mpack_node_i64(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {

                    p->arr_int64->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));
                    p->arr_int64->value = memory_platform.rf_calloc(p->arr_int64->count, sizeof (int64_t));
                    for (rfUint32 ii = 0; ii < p->arr_int64->count; ii++)
                        p->arr_int64->value[ii] =
                                mpack_node_i64(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->arr_int64->max = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->arr_int64->min = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "maxCount"))
                {
                    p->arr_int64->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->arr_int64->step = mpack_node_i64(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }
            }else if(rf_strcmp("flt_array_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {

                    p->arr_flt->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));
                    p->arr_flt->defValue = memory_platform.rf_calloc(p->arr_flt->defCount, sizeof (float));
                    for (rfUint32 ii = 0; ii < p->arr_flt->defCount; ii++)
                        p->arr_flt->defValue[ii] =
                                mpack_node_float(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {

                    p->arr_flt->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));
                    p->arr_flt->value = memory_platform.rf_calloc(p->arr_flt->count, sizeof (float));
                    for (rfUint32 ii = 0; ii < p->arr_flt->count; ii++)
                        p->arr_flt->value[ii] =
                                mpack_node_float(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->arr_flt->max = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->arr_flt->min = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "maxCount"))
                {
                    p->arr_flt->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->arr_flt->step = mpack_node_float(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }
            }else if(rf_strcmp("dbl_array_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {

                    p->arr_dbl->defCount =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "defaultValue"));
                    p->arr_dbl->defValue = memory_platform.rf_calloc(p->arr_dbl->defCount, sizeof (double));
                    for (rfUint32 ii = 0; ii < p->arr_dbl->defCount; ii++)
                        p->arr_dbl->defValue[ii] =
                                mpack_node_double(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "defaultValue"), ii));
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {

                    p->arr_dbl->count =
                            (rfUint32)mpack_node_array_length(
                                mpack_node_map_cstr(
                                    mpack_node_array_at(
                                        user, i), "value"));
                    p->arr_dbl->value = memory_platform.rf_calloc(p->arr_dbl->count, sizeof (double));
                    for (rfUint32 ii = 0; ii < p->arr_dbl->count; ii++)
                        p->arr_dbl->value[ii] =
                                mpack_node_double(
                                    mpack_node_array_at(
                                        mpack_node_map_cstr(
                                            mpack_node_array_at(
                                                user, i), "value"), ii));
                }
                // max
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "max"))
                {
                    p->arr_dbl->max = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(user, i), "max"));
                }
                // min
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "min"))
                {
                    p->arr_dbl->min = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(user, i), "min"));
                }
                // maxCount
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "maxCount"))
                {
                    p->arr_dbl->maxCount = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "maxCount"));
                }
                // step
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "step"))
                {
                    p->arr_dbl->step = mpack_node_double(mpack_node_map_cstr(mpack_node_array_at(user, i), "step"));
                }
            }else if(rf_strcmp("string_t", p->base.type) == 0)
            {
                // defaultValue
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "defaultValue"))
                {

                    size_t param_strlen = mpack_node_strlen(mpack_node_map_cstr(mpack_node_array_at(user, i), "defaultValue")) + 1;
                    p->val_str->defValue = mpack_node_cstr_alloc(mpack_node_map_cstr(mpack_node_array_at(user, i), "defaultValue"), param_strlen);
                }
                // value
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "value"))
                {

                    size_t param_strlen = mpack_node_strlen(mpack_node_map_cstr(mpack_node_array_at(user, i), "value")) + 1;
                    p->val_str->value = mpack_node_cstr_alloc(mpack_node_map_cstr(mpack_node_array_at(user, i), "value"), param_strlen);
                }
                // maxLen
                if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "maxLen"))
                {
                    p->val_str->maxLen = mpack_node_u32(mpack_node_map_cstr(mpack_node_array_at(user, i), "maxLen"));
                }
            }


            // index
            if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "index"))
            {
                p->base.index = mpack_node_uint(mpack_node_map_cstr(mpack_node_array_at(user, i), "index"));
            }

            // name
            if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "name"))
            {
                size_t param_strlen = mpack_node_strlen(mpack_node_map_cstr(mpack_node_array_at(user, i), "name")) + 1;
                p->base.name = mpack_node_cstr_alloc(mpack_node_map_cstr(mpack_node_array_at(user, i), "name"), param_strlen);
            }

            // offset
            if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "offset"))
            {
                p->base.offset = mpack_node_uint(mpack_node_map_cstr(mpack_node_array_at(user, i), "offset"));
            }

            // size
            if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "size"))
            {
                p->base.size = mpack_node_uint(mpack_node_map_cstr(mpack_node_array_at(user, i), "size"));
            }

            // units
            if (mpack_node_map_contains_cstr(mpack_node_array_at(user, i), "units"))
            {
                size_t param_strlen = mpack_node_strlen(mpack_node_map_cstr(mpack_node_array_at(user, i), "units")) + 1;
                p->base.units = mpack_node_cstr_alloc(mpack_node_map_cstr(mpack_node_array_at(user, i), "units"), param_strlen);
            }else
            {
                p->base.units = "";
            }

            vector_add(scanner->rf627_smart->params_list, p);
        }

        mpack_tree_destroy(&tree);

        // Answer:
        // {
        //    result: bool
        // }
        typedef struct
        {
            rfBool result;
        }answer;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }
        ((answer*)msg->result)->result = TRUE;

        status = TRUE;
    }

    return status;
}
rfInt8 rf627_smart_read_params_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_read_params_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: bool
        // }
        typedef struct
        {
            rfBool result;
        }answer;

        free((answer*)msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_read_params_from_scanner(rf627_smart_t* scanner, rfUint32 timeout)
{

    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "GET_PARAMS_DESCRIPTION";
    // payload - this is the data to be sent and their size
    char* payload                       = NULL;
    uint32_t payload_size               = 0;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_read_params_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_read_params_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_read_params_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    rfBool status = FALSE;
    // Send test msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: bool
            // }
            typedef struct
            {
                rfBool result;
            }answer;

            status = ((answer*)result)->result;

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ", status ? "RF_OK" : "PARSING_PROBLEM");
        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    // Cleanup msg
    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Write Params Method
//
rfInt8 rf627_smart_write_params_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    "parameter_1_name": String (*),
        //    "parameter_2_name": String (*),
        //     ...
        // }
        // * String: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* param_name;
            char* result;
        }param_result;

        typedef struct
        {
            uint32_t params_count;
            param_result* params;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        rfUint32 params_count = mpack_node_map_count(root);

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
            ((answer*)msg->result)->params_count = params_count;
            ((answer*)msg->result)->params = calloc(params_count, sizeof(param_result));
        }


        for (rfUint32 i = 0; i < params_count; i++)
        {
            ((answer*)msg->result)->params[i].param_name = mpack_node_cstr_alloc(
                        mpack_node_map_key_at(root, i), mpack_node_strlen(mpack_node_map_key_at(root, i)) + 1);
            ((answer*)msg->result)->params[i].result = mpack_node_cstr_alloc(
                        mpack_node_map_value_at(root, i), mpack_node_strlen(mpack_node_map_value_at(root, i)) + 1);
        }

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_write_params_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_write_params_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    "parameter_1_name": String (*),
        //    "parameter_2_name": String (*),
        //     ...
        // }
        // * String: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* param_name;
            char* result;
        }param_result;

        typedef struct
        {
            uint32_t params_count;
            param_result* params;
        }answer;

        for (uint32_t i = 0; i < ((answer*)msg->result)->params_count; i++)
        {
            free(((answer*)msg->result)->params[i].param_name);
            free(((answer*)msg->result)->params[i].result);
        }
        free(((answer*)msg->result)->params);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_write_params_to_scanner(rf627_smart_t* scanner, rfUint32 timeout)
{
    rfBool status = FALSE;

    int count = 0;
    rfSize param_list_size = vector_count(scanner->params_list);
    for(rfSize i = 0; i < param_list_size; i++)
    {
        parameter_t* p = vector_get(scanner->params_list, i);
        if (p->is_changed)
            count++;
    }

    if (count > 0)
    {
        // Create payload
        mpack_writer_t writer;
        rfChar* data = NULL; //< A growing array for msg.
        rfSize data_size = 0; //< Number of msg bytes.
        mpack_writer_init_growable(&writer, &data, &data_size);

        // Payload:
        // {
        //    "parameter_1_name": "parameter_1_value",
        //    "parameter_2_name": "parameter_2_value",
        //     ...
        // }

        // write to msg all parameters to change
        mpack_start_map(&writer, count);
        {
            for(rfSize i = 0; i < param_list_size; i++)
            {
                parameter_t* p = vector_get(scanner->params_list, i);
                if (p->is_changed)
                {
                    // Parameter name
                    mpack_write_cstr(&writer, p->base.name);
                    // Parameter value
                    if(rf_strcmp("uint32_t", p->base.type) == 0)
                    {
                        mpack_write_u32(&writer, p->val_uint32->value);
                    }else if(rf_strcmp("uint64_t", p->base.type) == 0)
                    {
                        mpack_write_u64(&writer, p->val_uint64->value);
                    }else if(rf_strcmp("int32_t", p->base.type) == 0)
                    {
                        mpack_write_i32(&writer, p->val_int32->value);
                    }else if(rf_strcmp("int64_t", p->base.type) == 0)
                    {
                        mpack_write_i64(&writer, p->val_int64->value);
                    }else if(rf_strcmp("float_t", p->base.type) == 0)
                    {
                        mpack_write_float(&writer, p->val_flt->value);
                    }else if(rf_strcmp("double_t", p->base.type) == 0)
                    {
                        mpack_write_double(&writer, p->val_dbl->value);
                    }else if(rf_strcmp("u32_arr_t", p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_uint32->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_uint32->count; ii++)
                                mpack_write_u32(&writer, p->arr_uint32->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp("u64_arr_t", p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_uint64->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_uint64->count; ii++)
                                mpack_write_u64(&writer, p->arr_uint64->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp("i32_arr_t", p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_int32->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_int32->count; ii++)
                                mpack_write_i32(&writer, p->arr_int32->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp("i64_arr_t", p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_int64->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_int64->count; ii++)
                                mpack_write_i64(&writer, p->arr_int64->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp("flt_array_t", p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_flt->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_flt->count; ii++)
                                mpack_write_float(&writer, p->arr_flt->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp("dbl_array_t", p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_dbl->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_dbl->count; ii++)
                                mpack_write_double(&writer, p->arr_dbl->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp("string_t", p->base.type) == 0)
                    {
                        mpack_write_str(&writer, p->val_str->value, p->base.size);
                    }
                    p->is_changed = FALSE;
                }

            }
        }mpack_finish_map(&writer);

        // finish writing
        if (mpack_writer_destroy(&writer) != mpack_ok) {
            fprintf(stderr, "An error occurred encoding the data!\n");
            return FALSE;
        }

        // cmd_name - this is logical port/path where data will be send
        char* cmd_name                      = "SET_PARAMETERS";
        // payload - this is the data to be sent and their size
        char* payload                       = data;
        uint32_t payload_size               = (uint32_t)data_size;
        // data_type - this is the type of packaging of the sent data
        char* data_type                     = "mpack"; // mpack, json, blob..
        uint8_t is_check_crc                = FALSE;   // check crc disabled
        uint8_t is_confirmation             = TRUE;    // confirmation enabled
        uint8_t is_one_answ                 = TRUE;    // wait only one answer
        uint32_t waiting_time               = timeout; // ms
        uint32_t resends                    = is_confirmation ? 3 : 0;
        // callbacks for request
        RF62X_answ_callback answ_clb        = rf627_smart_write_params_callback;
        RF62X_timeout_callback timeout_clb  = rf627_smart_write_params_timeout_callback;
        RF62X_free_callback free_clb        = rf627_smart_write_params_free_result_callback;

        rf627_smart_protocol_cmd_settings_t* p = NULL;
        pthread_mutex_lock(&scanner->protocol_settings_mutex);
        for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
        {
            p = vector_get(scanner->protocol_settings_list, i);
            if (rf_strcmp(p->cmd_name, cmd_name) == 0)
            {
                is_check_crc = p->is_check_crc;
                is_confirmation = p->is_confirmation;
                is_one_answ = p->is_one_answ;
                waiting_time = p->waiting_time;
                resends = is_confirmation ? p->resends_count : 0;
                break;
            }
        }
        pthread_mutex_unlock(&scanner->protocol_settings_mutex);

        // Create request message
        RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                                 is_check_crc, is_confirmation, is_one_answ,
                                                 waiting_time, resends,
                                                 answ_clb, timeout_clb, free_clb);
        // free memory of payload
        free(payload);

        // Send test msg
        if (RF62X_channel_send_msg(&scanner->channel, msg))
        {
            TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

            // try to find answer to rqst
            pthread_mutex_lock(msg->result_mutex);
            void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
            if (result != NULL)
            {
                // Answer:
                // {
                //    "parameter_1_name": String (*),
                //    "parameter_2_name": String (*),
                //     ...
                // }
                // * String: displays the result according to the response codes.
                //           On successful execution "RF_OK".
                typedef struct
                {
                    char* param_name;
                    char* result;
                }param_result;

                typedef struct
                {
                    uint32_t params_count;
                    param_result* params;
                }answer;

                status = TRUE;
                for (uint32_t i = 0; i < ((answer*)result)->params_count; i++)
                {
                    if (rf_strcmp(((answer*)result)->params[i].result, "RF_OK") != 0)
                    {
                        status = FALSE;
                        TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,
                              "Parameter \"%s\" hasn't been set. "
                              "Reason for failure: %s\n",
                              ((answer*)result)->params[i].param_name,
                              ((answer*)result)->params[i].result);
                    }
                }

                int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
                int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
                TRACE(TRACE_LEVEL, TRACE_FORMAT,
                      "%s%s PARAMETERS HAS BEEN SET\n",
                      "Get response to request! "
                      "Response status: ",status ? "ALL" : "NOT ALL");
            }else
            {
                TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
            }
            pthread_mutex_unlock(msg->result_mutex);
        }
        else
        {
            TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
        }

        RF62X_cleanup_msg(msg);
        free(msg); msg = NULL;
    }

    return status;
}


//
// RF627-Smart (v2.x.x)
// Save Params Method
//
rfInt8 rf627_smart_save_params_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    if (existing)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        mpack_node_t result_data = mpack_node_map_cstr(root, "result");
        uint32_t result_size = mpack_node_strlen(result_data) + 1;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->result =
                mpack_node_cstr_alloc(result_data, result_size);

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_save_params_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_save_params_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_save_params_to_scanner(rf627_smart_t* scanner, rfUint32 timeout)
{
    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "SAVE_PARAMETERS";
    // payload - this is the data to be sent and their size
    char* payload                       = NULL;
    uint32_t payload_size               = 0;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_save_params_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_save_params_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_save_params_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: String (*)
            // }
            // * result: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            typedef struct
            {
                char* result;
            }answer;

            if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0)
                status = TRUE;
            else
                status = FALSE;

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ",((answer*)result)->result);

        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Save Recovery Params Method
//
rfInt8 rf627_smart_save_recovery_params_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        mpack_node_t result_data = mpack_node_map_cstr(root, "result");
        uint32_t result_size = mpack_node_strlen(result_data) + 1;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->result =
                mpack_node_cstr_alloc(result_data, result_size);

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_save_recovery_params_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_save_recovery_params_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_save_recovery_params_to_scanner(rf627_smart_t* scanner, rfUint32 timeout)
{
    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "SAVE_RECOVERY_PARAMETERS";
    // payload - this is the data to be sent and their size
    char* payload                       = NULL;
    uint32_t payload_size               = 0;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_save_recovery_params_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_save_recovery_params_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_save_recovery_params_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: String (*)
            // }
            // * result: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            typedef struct
            {
                char* result;
            }answer;

            if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0)
                status = TRUE;
            else
                status = FALSE;

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ",((answer*)result)->result);

        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Load Recovery Params Method
//
rfInt8 rf627_smart_load_recovery_params_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        mpack_node_t result_data = mpack_node_map_cstr(root, "result");
        uint32_t result_size = mpack_node_strlen(result_data) + 1;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->result =
                mpack_node_cstr_alloc(result_data, result_size);

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_load_recovery_params_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_load_recovery_params_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_load_recovery_params_from_scanner(rf627_smart_t* scanner, rfUint32 timeout)
{
    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "LOAD_RECOVERY_PARAMETERS";
    // payload - this is the data to be sent and their size
    char* payload                       = NULL;
    uint32_t payload_size               = 0;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_load_recovery_params_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_load_recovery_params_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_load_recovery_params_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: String (*)
            // }
            // * result: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            typedef struct
            {
                char* result;
            }answer;

            if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0)
                status = TRUE;
            else
                status = FALSE;

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ",((answer*)result)->result);

        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Get Frame Method
//
rfInt8 rf627_smart_get_frame_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    frame: Blob (*),
        //    user_roi_active: Bool,
        //    user_roi_enabled: Bool,
        //    user_roi_pos: Number (uint32_t),
        //    user_roi_size: Number (uint32_t)
        //    frame_width: Number (uint32_t)
        //    frame_height: Number (uint32_t)
        //    fact_sensor_width: Number (uint32_t)
        //    fact_sensor_height: Number (uint32_t)
        // }
        // * Blob: an array of bytes with a matrix frame, each byte is
        //         responsible for the brightness of the pixel starting from
        //         the upper left pixel.
        typedef struct
        {
            rfBool status;
            union
            {
                rf627_smart_frame_t* frame;
                char* result;
            };
        }answer;
        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        mpack_node_t root = mpack_tree_root(&tree);
        if (mpack_node_map_contains_cstr(root, "frame"))
        {
            ((answer*)msg->result)->status = TRUE;
            if (((answer*)msg->result)->frame == NULL)
            {
                ((answer*)msg->result)->frame = calloc(1, sizeof (rf627_smart_frame_t));
            }
            rf627_smart_frame_t* frame = ((answer*)msg->result)->frame;
            mpack_node_t frame_data = mpack_node_map_cstr(root, "frame");
            uint32_t frame_size = mpack_node_data_len(frame_data);

            frame->data_size = frame_size;
            frame->data = (char*)mpack_node_data_alloc(frame_data, frame_size+1);

            if (mpack_node_map_contains_cstr(root, "user_roi_active"))
            {
                mpack_node_t frame_roi_active = mpack_node_map_cstr(root, "user_roi_active");
                frame->user_roi_active = mpack_node_bool(frame_roi_active);
            }

            if (mpack_node_map_contains_cstr(root, "user_roi_enabled"))
            {
                mpack_node_t frame_roi_enabled = mpack_node_map_cstr(root, "user_roi_enabled");
                frame->user_roi_enabled = mpack_node_bool(frame_roi_enabled);
            }

            if (mpack_node_map_contains_cstr(root, "user_roi_pos"))
            {
                mpack_node_t frame_roi_pos = mpack_node_map_cstr(root, "user_roi_pos");
                frame->user_roi_pos = mpack_node_u32(frame_roi_pos);
            }

            if (mpack_node_map_contains_cstr(root, "user_roi_size"))
            {
                mpack_node_t frame_roi_size = mpack_node_map_cstr(root, "user_roi_size");
                frame->user_roi_size = mpack_node_u32(frame_roi_size);
            }

            if (mpack_node_map_contains_cstr(root, "frame_width"))
            {
                mpack_node_t frame_width = mpack_node_map_cstr(root, "frame_width");
                frame->frame_width = mpack_node_u32(frame_width);
            }else
            {
                frame->frame_width = 0;
            }

            if (mpack_node_map_contains_cstr(root, "frame_height"))
            {
                mpack_node_t frame_height = mpack_node_map_cstr(root, "frame_height");
                frame->frame_height = mpack_node_u32(frame_height);
            }else
            {
                frame->frame_height = 0;
            }

            if (mpack_node_map_contains_cstr(root, "fact_sensor_width"))
            {
                mpack_node_t fact_sensor_width = mpack_node_map_cstr(root, "fact_sensor_width");
                frame->fact_sensor_width = mpack_node_u32(fact_sensor_width);
            }else
            {
                frame->fact_sensor_width = 0;
            }

            if (mpack_node_map_contains_cstr(root, "fact_sensor_height"))
            {
                mpack_node_t fact_sensor_height = mpack_node_map_cstr(root, "fact_sensor_height");
                frame->fact_sensor_height = mpack_node_u32(fact_sensor_height);
            }else
            {
                frame->fact_sensor_height = 0;
            }

            status = TRUE;
        }else
        {
            // Answer:
            // {
            //    result: String (*)
            // }
            // * result: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            mpack_node_t result_data = mpack_node_map_cstr(root, "result");
            uint32_t result_size = mpack_node_strlen(result_data) + 1;

            ((answer*)msg->result)->status = FALSE;
            ((answer*)msg->result)->result =
                    mpack_node_cstr_alloc(result_data, result_size);

            status = TRUE;
        }
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_get_frame_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_get_frame_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    frame: Blob (*),
        //    user_roi_active: Bool,
        //    user_roi_enabled: Bool,
        //    user_roi_pos: Number (uint32_t),
        //    user_roi_size: Number (uint32_t)
        //    frame_width: Number (uint32_t)
        //    frame_height: Number (uint32_t)
        //    fact_sensor_width: Number (uint32_t)
        //    fact_sensor_height: Number (uint32_t)
        // }
        // * Blob: an array of bytes with a matrix frame, each byte is
        //         responsible for the brightness of the pixel starting from
        //         the upper left pixel.
        typedef struct
        {
            rfBool status;
            union
            {
                rf627_smart_frame_t* frame;
                char* result;
            };
        }answer;

        answer* answ = msg->result;

        if (answ->status)
        {
            free(answ->frame->data);
            free(answ->frame);
        }else
        {
            free(answ->result);
        }

        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rf627_smart_frame_t* rf627_smart_get_frame(rf627_smart_t* scanner, rfUint32 timeout)
{
    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "GET_FRAME";
    // payload - this is the data to be sent and their size
    char* payload                       = NULL;
    uint32_t payload_size               = 0;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_get_frame_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_get_frame_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_get_frame_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    rf627_smart_frame_t* frame = NULL;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            typedef struct
            {
                rfBool status;
                union
                {
                    rf627_smart_frame_t* frame;
                    char* result;
                };
            }answer;

            answer* answ = result;

            if (answ->status)
            {
                frame = calloc(1, sizeof (rf627_smart_frame_t));
                frame->data_size = answ->frame->data_size;
                frame->data = calloc(frame->data_size, sizeof (rfChar));
                memcpy(frame->data, (char*)answ->frame->data, frame->data_size);
                frame->frame_height = answ->frame->frame_height;
                frame->frame_width = answ->frame->frame_width;

                frame->user_roi_active = answ->frame->user_roi_active;

                frame->user_roi_enabled = answ->frame->user_roi_enabled;
                frame->user_roi_pos = answ->frame->user_roi_pos;
                frame->user_roi_size = answ->frame->user_roi_size;
                frame->fact_sensor_height = answ->frame->fact_sensor_height;
                frame->fact_sensor_width = answ->frame->fact_sensor_width;


                TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
                      "%s%s\n",
                      "Get response to request! "
                      "Response status: ", "RF_OK");
            }else
            {
                TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,
                      "%s%s\n",
                      "Get response to request! "
                      "Response status: ",answ->result);
            }
        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return frame;
}


//
// RF627-Smart (v2.x.x)
// Get Dumps Profiles Method
//
rfInt8 rf627_smart_get_dumps_profiles_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        typedef struct
        {
            char* data;
            uint32_t data_size;
        }answer;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
            ((answer*)msg->result)->data = calloc(data_size, sizeof (char));
            memcpy(((answer*)msg->result)->data, data, data_size);
            ((answer*)msg->result)->data_size = data_size;
        }

        status = TRUE;
    }

    return status;
}
rfInt8 rf627_smart_get_dumps_profiles_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_get_dumps_profiles_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        typedef struct
        {
            char* data;
            uint32_t data_size;
        }answer;

        free(((answer*)msg->result)->data);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_get_dumps_profiles_by_service_protocol(
        rf627_smart_t* scanner, uint32_t index, uint32_t count,  rfUint32 timeout,
        rf627_profile2D_t** profile_array, uint32_t* array_count, uint32_t dump_unit_size)
{
    // Create payload
    mpack_writer_t writer;
    rfChar* data = NULL; //< A growing array for msg.
    rfSize data_size = 0; //< Number of msg bytes.
    mpack_writer_init_growable(&writer, &data, &data_size);

    // Payload:
    // {
    //    index: Number (uint32_t)
    //    count: Number (uint32_t)
    // }
    // * index: the number of the requested profile from memory;
    //   count: the number of requested profiles, starting from the profile
    //          specified in index;
    mpack_start_map(&writer, 2);
    {
        mpack_write_cstr(&writer, "index");
        mpack_write_uint(&writer, index);

        mpack_write_cstr(&writer, "count");
        mpack_write_uint(&writer, count);
    }mpack_finish_map(&writer);

    // finish writing
    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");
        return FALSE;
    }

    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "GET_DUMP_DATA";
    // payload - this is the data to be sent and their size
    char* payload                       = data;
    uint32_t payload_size               = (uint32_t)data_size;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "mpack"; // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = TRUE;    // confirmation enabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_get_dumps_profiles_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_get_dumps_profiles_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_get_dumps_profiles_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);
    // free memory of payload
    free(payload);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            typedef struct
            {
                char* data;
                uint32_t data_size;
            }answer;

            *array_count = ((answer*)result)->data_size / dump_unit_size;

            for (uint32_t i = 0; i < *array_count; i++)
            {
                profile_array[i] = memory_platform.rf_calloc(1, sizeof (rf627_profile2D_t));
                profile_array[i]->rf627smart_profile2D =
                        memory_platform.rf_calloc(1, sizeof(rf627_smart_profile2D_t));

                profile_array[i]->type = kRF627_SMART;

                rf627_old_stream_msg_t header_from_msg = rf627_protocol_old_unpack_header_msg_from_profile_packet((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])));

                profile_array[i]->rf627smart_profile2D->header.data_type = header_from_msg.data_type;
                profile_array[i]->rf627smart_profile2D->header.flags = header_from_msg.flags;
                profile_array[i]->rf627smart_profile2D->header.device_type = header_from_msg.device_type;
                profile_array[i]->rf627smart_profile2D->header.serial_number = header_from_msg.serial_number;
                profile_array[i]->rf627smart_profile2D->header.system_time = header_from_msg.system_time;

                profile_array[i]->rf627smart_profile2D->header.proto_version_major = header_from_msg.proto_version_major;
                profile_array[i]->rf627smart_profile2D->header.proto_version_minor = header_from_msg.proto_version_minor;
                profile_array[i]->rf627smart_profile2D->header.hardware_params_offset = header_from_msg.hardware_params_offset;
                profile_array[i]->rf627smart_profile2D->header.data_offset = header_from_msg.data_offset;
                profile_array[i]->rf627smart_profile2D->header.packet_count = header_from_msg.packet_count;
                profile_array[i]->rf627smart_profile2D->header.measure_count = header_from_msg.measure_count;

                profile_array[i]->rf627smart_profile2D->header.zmr = header_from_msg.zmr;
                profile_array[i]->rf627smart_profile2D->header.xemr = header_from_msg.xemr;
                profile_array[i]->rf627smart_profile2D->header.discrete_value = header_from_msg.discrete_value;

                profile_array[i]->rf627smart_profile2D->header.exposure_time = header_from_msg.exposure_time;
                profile_array[i]->rf627smart_profile2D->header.laser_value = header_from_msg.laser_value;
                profile_array[i]->rf627smart_profile2D->header.step_count = header_from_msg.step_count;
                profile_array[i]->rf627smart_profile2D->header.dir = header_from_msg.dir;
                profile_array[i]->rf627smart_profile2D->header.payload_size = header_from_msg.payload_size;
                profile_array[i]->rf627smart_profile2D->header.bytes_per_point = header_from_msg.bytes_per_point;

                if(profile_array[i]->rf627smart_profile2D->header.serial_number == scanner->info_by_service_protocol.fact_general_serial)
                {
                    rfInt16 x;
                    rfUint16 z;

                    rfUint32 pt_count;
                    switch (profile_array[i]->rf627smart_profile2D->header.data_type)
                    {
                    case DTY_PixelsNormal:
                        pt_count = profile_array[i]->rf627smart_profile2D->header.payload_size / profile_array[i]->rf627smart_profile2D->header.bytes_per_point;
                        profile_array[i]->rf627smart_profile2D->pixels_format.pixels_count = 0;
                        profile_array[i]->rf627smart_profile2D->pixels_format.pixels =
                                memory_platform.rf_calloc(pt_count, sizeof (rfUint16));
                        if (profile_array[i]->rf627smart_profile2D->header.flags & 0x01){
                            profile_array[i]->rf627smart_profile2D->intensity_count = 0;
                            profile_array[i]->rf627smart_profile2D->intensity =
                                    memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                        }
                        break;
                    case DTY_ProfileNormal:
                        pt_count = profile_array[i]->rf627smart_profile2D->header.payload_size / profile_array[i]->rf627smart_profile2D->header.bytes_per_point;
                        profile_array[i]->rf627smart_profile2D->profile_format.points_count = 0;
                        profile_array[i]->rf627smart_profile2D->profile_format.points =
                                memory_platform.rf_calloc(pt_count, sizeof (rf627_old_point2D_t));
                        if (profile_array[i]->rf627smart_profile2D->header.flags & 0x01){
                            profile_array[i]->rf627smart_profile2D->intensity_count = 0;
                            profile_array[i]->rf627smart_profile2D->intensity =
                                    memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                        }
                        break;
                    case DTY_PixelsInterpolated:
                        pt_count = profile_array[i]->rf627smart_profile2D->header.payload_size / profile_array[i]->rf627smart_profile2D->header.bytes_per_point;
                        profile_array[i]->rf627smart_profile2D->pixels_format.pixels_count = 0;
                        profile_array[i]->rf627smart_profile2D->pixels_format.pixels =
                                memory_platform.rf_calloc(pt_count, sizeof (rfUint16));
                        if (profile_array[i]->rf627smart_profile2D->header.flags & 0x01){
                            profile_array[i]->rf627smart_profile2D->intensity_count = 0;
                            profile_array[i]->rf627smart_profile2D->intensity =
                                    memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                        }
                        break;
                    case DTY_ProfileInterpolated:
                        pt_count = profile_array[i]->rf627smart_profile2D->header.payload_size / profile_array[i]->rf627smart_profile2D->header.bytes_per_point;
                        profile_array[i]->rf627smart_profile2D->profile_format.points_count = 0;
                        profile_array[i]->rf627smart_profile2D->profile_format.points =
                                memory_platform.rf_calloc(pt_count, sizeof (rf627_old_point2D_t));
                        if (profile_array[i]->rf627smart_profile2D->header.flags & 0x01){
                            profile_array[i]->rf627smart_profile2D->intensity_count = 0;
                            profile_array[i]->rf627smart_profile2D->intensity =
                                    memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                        }
                        break;
                    }

                    rfUint32 profile_header_size =
                            rf627_protocol_old_get_size_of_response_profile_header_packet();
                    rfBool zero_points = TRUE;

                    for (rfUint32 ii=0; ii<pt_count; ii++)
                    {
                        rf627_old_point2D_t pt;
                        switch (profile_array[i]->rf627smart_profile2D->header.data_type)
                        {
                        case DTY_ProfileNormal:
                        case DTY_ProfileInterpolated:
                            z = *(rfUint16*)(&((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + ii*4 + 2]);
                            x = *(rfInt16*)(&((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + ii*4]);
                            if (zero_points == 0 && z > 0)
                            {
                                pt.x = (rfFloat)((rfDouble)(x) * (rfDouble)(profile_array[i]->rf627smart_profile2D->header.xemr) /
                                                 (rfDouble)(profile_array[i]->rf627smart_profile2D->header.discrete_value));
                                pt.z = (rfFloat)((rfDouble)(z) * (rfDouble)(profile_array[i]->rf627smart_profile2D->header.zmr) /
                                                 (rfDouble)(profile_array[i]->rf627smart_profile2D->header.discrete_value));

                                profile_array[i]->rf627smart_profile2D->profile_format.points[profile_array[i]->rf627smart_profile2D->profile_format.points_count] = pt;
                                profile_array[i]->rf627smart_profile2D->profile_format.points_count++;
                                if (profile_array[i]->rf627smart_profile2D->header.flags & 0x01)
                                {
                                    profile_array[i]->rf627smart_profile2D->intensity[profile_array[i]->rf627smart_profile2D->intensity_count] = ((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + pt_count*4 + ii];
                                    profile_array[i]->rf627smart_profile2D->intensity_count++;
                                }
                            }else if(zero_points != 0)
                            {
                                pt.x = (rfFloat)((rfDouble)(x) * (rfDouble)(profile_array[i]->rf627smart_profile2D->header.xemr) /
                                                 (rfDouble)(profile_array[i]->rf627smart_profile2D->header.discrete_value));
                                pt.z = (rfFloat)((rfDouble)(z) * (rfDouble)(profile_array[i]->rf627smart_profile2D->header.zmr) /
                                                 (rfDouble)(profile_array[i]->rf627smart_profile2D->header.discrete_value));

                                profile_array[i]->rf627smart_profile2D->profile_format.points[profile_array[i]->rf627smart_profile2D->profile_format.points_count] = pt;
                                profile_array[i]->rf627smart_profile2D->profile_format.points_count++;
                                if (profile_array[i]->rf627smart_profile2D->header.flags & 0x01)
                                {
                                    profile_array[i]->rf627smart_profile2D->intensity[profile_array[i]->rf627smart_profile2D->intensity_count] = ((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + pt_count*4 + ii];
                                    profile_array[i]->rf627smart_profile2D->intensity_count++;
                                }
                            }
                            break;
                        case DTY_PixelsNormal:
                        case DTY_PixelsInterpolated:
                            z = *(rfUint16*)(&((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + ii*2]);
                            //pt.x = i;

                            profile_array[i]->rf627smart_profile2D->pixels_format.pixels[profile_array[i]->rf627smart_profile2D->pixels_format.pixels_count] = z;
                            profile_array[i]->rf627smart_profile2D->pixels_format.pixels_count++;
                            if (profile_array[i]->rf627smart_profile2D->header.flags & 0x01)
                            {
                                profile_array[i]->rf627smart_profile2D->intensity[profile_array[i]->rf627smart_profile2D->intensity_count] = ((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + pt_count*4 + ii];
                                profile_array[i]->rf627smart_profile2D->intensity_count++;
                            }

                            //pt.z = (rfDouble)(z) / (rfDouble)(profile->header.discrete_value);

                            break;
                        }

                    }
                }
            }

            if (*array_count > 0)
                status = TRUE;
            else
                status = FALSE;

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%d\n",
                  "Get response to request! "
                  "Received profiles: ",*array_count);
        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Get Authorization Token Method
//
rfInt8 rf627_smart_get_authorization_token_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        typedef struct
        {
            uint32_t status;
            char* token;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        mpack_node_t token_data = mpack_node_map_cstr(root, "token");
        uint32_t token_size = mpack_node_strlen(token_data) + 1;
        mpack_node_t status_data = mpack_node_map_cstr(root, "status");

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->token = mpack_node_cstr_alloc(token_data, token_size);
        ((answer*)msg->result)->status = mpack_node_u32(status_data);

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_get_authorization_token_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_get_authorization_token_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        typedef struct
        {
            uint32_t status;
            char* token;
        }answer;

        free(((answer*)msg->result)->token);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_get_authorization_token_by_service_protocol(rf627_smart_t* scanner, char** token, rfUint32* token_size, rfUint32 timeout)
{
    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "GET_AUTHORIZATION_TOKEN";
    // payload - this is the data to be sent and their size
    char* payload                       = NULL;
    uint32_t payload_size               = 0;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_get_authorization_token_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_get_authorization_token_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_get_authorization_token_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    status: Number (uint32_t) (*),
            //    token: String
            // }
            // * status: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            typedef struct
            {
                uint32_t status;
                char* token;
            }answer;


            status = TRUE;

            *token_size = rf_strlen(((answer*)result)->token);
            *token = calloc(*token_size + 1, sizeof (char));
            memcpy(*token, ((answer*)result)->token, *token_size);

            TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ", ((answer*)result)->status != 0 ?
                        "STATUS_FACTORY" : "AUTH_STATUS_USER");
        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Set Authorization Key Method
//
rfInt8 rf627_smart_set_authorization_key_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    result: String (*)
        //    status: Number
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
            uint32_t status;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        mpack_node_t result_data = mpack_node_map_cstr(root, "result");
        uint32_t result_size = (rfUint32)mpack_node_strlen(result_data) + 1;
        mpack_node_t status_data = mpack_node_map_cstr(root, "status");

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->result = mpack_node_cstr_alloc(result_data, result_size);
        ((answer*)msg->result)->status = mpack_node_u32(status_data);

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_set_authorization_key_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_set_authorization_key_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: String (*)
        //    status: Number
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
            uint32_t status;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_set_authorization_key_by_service_protocol(rf627_smart_t* scanner, char* key, rfUint32 key_size, rfUint32 timeout)
{
    // Create payload
    mpack_writer_t writer;
    rfChar* data = NULL; //< A growing array for msg.
    rfSize data_size = 0; //< Number of msg bytes.
    mpack_writer_init_growable(&writer, &data, &data_size);


    // Payload:
    // {
    //    key: String
    // }
    mpack_start_map(&writer, 1);
    {
        mpack_write_cstr(&writer, "key");
        mpack_write_cstr(&writer, key);
    }mpack_finish_map(&writer);

    // finish writing
    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");
        return FALSE;
    }

    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "SET_AUTHORIZATION_KEY";
    // payload - this is the data to be sent and their size
    char* payload                       = data;
    uint32_t payload_size               = (uint32_t)data_size;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "mpack"; // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_set_authorization_key_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_set_authorization_key_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_set_authorization_key_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);
    // free memory of payload
    free(payload);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: String (*)
            //    status: Number
            // }
            // * result: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            typedef struct
            {
                char* result;
                uint32_t status;
            }answer;

            if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0)
                status = TRUE;
            else
                status = FALSE;

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ",((answer*)result)->result);

        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


rfBool rf627_smart_create_calibration_table(rf627_smart_t* scanner, rfUint32 timeout)
{
    if (scanner->calib_table.m_Data != NULL)
        free(scanner->calib_table.m_Data);

    scanner->calib_table.m_Data = NULL;
    scanner->calib_table.m_DataSize = 0;

    scanner->calib_table.m_Type = 0x05;

    scanner->calib_table.m_Serial = scanner->info_by_service_protocol.fact_general_serial;
    scanner->calib_table.m_DataRowLength = 8192;
    scanner->calib_table.m_Width = rf627_smart_get_parameter(
                scanner, "fact_sensor_width")->val_uint32->value;
    scanner->calib_table.m_Height = rf627_smart_get_parameter(
                scanner, "fact_sensor_height")->val_uint32->value;


    scanner->calib_table.m_MultW = 1;
    scanner->calib_table.m_MultH = 2;

    scanner->calib_table.m_TimeStamp = time(NULL);

    scanner->calib_table.m_CRC16 = 0;

    return TRUE;
}

//
// RF627-Smart (v2.x.x)
// Read Calibration Data Method (TODO Parse Type)
//
rfInt8 rf627_smart_read_calibration_data_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //     result: String (*),
        //     serial: Number (uint32_t),
        //     data_row_length: Number (uint32_t),
        //     width: Number (uint32_t),
        //     height: Number (uint32_t),
        //     mult_w: Number (uint32_t),
        //     mult_h: Number (uint32_t),
        //     time_stamp: Number (uint64_t)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;

            rfUint32 serial;
            rfUint32 data_row_length;
            rfUint32 width;
            rfUint32 height;
            rfUint32 mult_w;
            rfUint32 mult_h;
            rfInt time_stamp;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        if (mpack_node_map_contains_cstr(root, "result"))
        {
            if (msg->result == NULL)
            {
                msg->result = calloc(1, sizeof (answer));
            }
            answer* answ =  (answer*)msg->result;

            mpack_node_t result_data = mpack_node_map_cstr(root, "result");
            uint32_t result_size = (rfUint32)mpack_node_strlen(result_data) + 1;
            answ->result = mpack_node_cstr_alloc(result_data, result_size);

            if (rf_strcmp(answ->result, "RF_OK") == 0)
            {
                if (mpack_node_map_contains_cstr(root, "serial"))
                {
                    mpack_node_t serial = mpack_node_map_cstr(root, "serial");
                    answ->serial = mpack_node_u32(serial);
                }
                if (mpack_node_map_contains_cstr(root, "data_row_length"))
                {
                    mpack_node_t data_row_length = mpack_node_map_cstr(root, "data_row_length");
                    answ->data_row_length = mpack_node_u32(data_row_length);
                }
                if (mpack_node_map_contains_cstr(root, "width"))
                {
                    mpack_node_t width = mpack_node_map_cstr(root, "width");
                    answ->width = mpack_node_u32(width);
                }
                if (mpack_node_map_contains_cstr(root, "height"))
                {
                    mpack_node_t height = mpack_node_map_cstr(root, "height");
                    answ->height = mpack_node_u32(height);
                }
                if (mpack_node_map_contains_cstr(root, "mult_w"))
                {
                    mpack_node_t mult_w = mpack_node_map_cstr(root, "mult_w");
                    answ->mult_w = mpack_node_u32(mult_w);
                }
                if (mpack_node_map_contains_cstr(root, "mult_h"))
                {
                    mpack_node_t mult_h = mpack_node_map_cstr(root, "mult_h");
                    answ->mult_h = mpack_node_u32(mult_h);
                }
                if (mpack_node_map_contains_cstr(root, "time_stamp"))
                {
                    mpack_node_t time_stamp = mpack_node_map_cstr(root, "time_stamp");
                    answ->time_stamp = mpack_node_i32(time_stamp);
                }
            }
            status = TRUE;
        }
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_read_calibration_data_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_read_calibration_data_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //     result: String (*),
        //     serial: Number (uint32_t),
        //     data_row_length: Number (uint32_t),
        //     width: Number (uint32_t),
        //     height: Number (uint32_t),
        //     mult_w: Number (uint32_t),
        //     mult_h: Number (uint32_t),
        //     time_stamp: Number (uint64_t)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;

            rfUint32 serial;
            rfUint32 data_row_length;
            rfUint32 width;
            rfUint32 height;
            rfUint32 mult_w;
            rfUint32 mult_h;
            rfInt time_stamp;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_read_calibration_table_by_service_protocol(rf627_smart_t* scanner, rfUint32 timeout)
{
    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "GET_CALIBRATION_INFO";
    // payload - this is the data to be sent and their size
    char* payload                       = NULL;
    uint32_t payload_size               = 0;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_read_calibration_data_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_read_calibration_data_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_read_calibration_data_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //     result: String (*),
            //     serial: Number (uint32_t),
            //     data_row_len: Number (uint32_t),
            //     width: Number (uint32_t),
            //     height: Number (uint32_t),
            //     mult_w: Number (uint32_t),
            //     mult_h: Number (uint32_t),
            //     time_stamp: Number (uint64_t)
            // }
            // * result: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            typedef struct
            {
                char* result;

                rfUint32 serial;
                rfUint32 data_row_len;
                rfUint32 width;
                rfUint32 height;
                rfUint32 mult_w;
                rfUint32 mult_h;
                rfInt time_stamp;
            }answer;

            answer* answ = (answer*)result;

            if (rf_strcmp(answ->result, "RF_OK") == 0)
            {
                status = TRUE;
                if (scanner->calib_table.m_Data != NULL)
                    free(scanner->calib_table.m_Data);

                scanner->calib_table.m_Data = NULL;
                scanner->calib_table.m_DataSize = 0;

                scanner->calib_table.m_Type = 0x05;

                scanner->calib_table.m_Serial = answ->serial;
                scanner->calib_table.m_DataRowLength = answ->data_row_len;
                scanner->calib_table.m_Width = answ->width;
                scanner->calib_table.m_Height = answ->height;

                scanner->calib_table.m_MultW = answ->mult_w;
                scanner->calib_table.m_MultH = answ->mult_h;

                scanner->calib_table.m_TimeStamp = answ->time_stamp;

                scanner->calib_table.m_CRC16 = 0;
            }else
            {
                status = FALSE;
            }

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ",((answer*)result)->result);

        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    if (status == FALSE)
    {
        if (scanner->calib_table.m_Data != NULL)
            free(scanner->calib_table.m_Data);

        scanner->calib_table.m_Data = NULL;
        scanner->calib_table.m_DataSize = 0;

        scanner->calib_table.m_Type = 0x05;

        scanner->calib_table.m_Serial = scanner->info_by_service_protocol.fact_general_serial;
        scanner->calib_table.m_DataRowLength = 8192;
        scanner->calib_table.m_Width = rf627_smart_get_parameter(
                    scanner, "fact_sensor_width")->val_uint32->value;
        scanner->calib_table.m_Height = rf627_smart_get_parameter(
                    scanner, "fact_sensor_height")->val_uint32->value;


        scanner->calib_table.m_MultW = 1;
        scanner->calib_table.m_MultH = 2;

        scanner->calib_table.m_TimeStamp = time(NULL);

        scanner->calib_table.m_CRC16 = 0;
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Write Calibration Data Method
//
extern uint16_t crc16(const uint8_t *data, uint32_t len);
rfInt8 rf627_smart_write_calibration_data_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        mpack_node_t result_data = mpack_node_map_cstr(root, "result");
        uint32_t result_size = mpack_node_strlen(result_data) + 1;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->result =
                mpack_node_cstr_alloc(result_data, result_size);

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_write_calibration_data_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_write_calibration_data_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_write_calibration_data_by_service_protocol(rf627_smart_t* scanner, rfUint32 timeout)
{
    // Create payload
    mpack_writer_t writer;
    char* body = NULL; //< A growing array for msg.
    size_t body_size = 0;	//< Number of msg bytes.
    mpack_writer_init_growable(&writer, &body, &body_size);

    // Payload:
    // header: (bin)
    // {
    //    body_size (uint32_t) - size of mpack msg
    //    data_offset (uint32_t) - header_size + body_size + trail_size
    // }
    // body: (mpack)
    // {
    //    type: Number (uint32_t)
    //    serial: Number (uint32_t)
    //    data_size: Number (uint32_t)
    //    data_row_length: Number (uint32_t)
    //    width: Number (uint32_t)
    //    height: Number (uint32_t)
    //    mult_w: Number (uint32_t)
    //    mult_h: Number (uint32_t)
    //    time_stamp: Number (uint32_t)
    //    crc: Number (uint32_t)
    // }
    // payload: (bin)
    // {
    //    trail (bin)
    //    data (bin)
    // }

    // Create body
    mpack_start_map(&writer, 10);
    {
        mpack_write_cstr(&writer, "type");
        mpack_write_uint(&writer, scanner->calib_table.m_Type);

        mpack_write_cstr(&writer, "serial");
        mpack_write_uint(&writer, scanner->calib_table.m_Serial);

        mpack_write_cstr(&writer, "data_size");
        mpack_write_uint(&writer, scanner->calib_table.m_DataSize);

        mpack_write_cstr(&writer, "data_row_length");
        mpack_write_uint(&writer, scanner->calib_table.m_DataRowLength);

        mpack_write_cstr(&writer, "width");
        mpack_write_uint(&writer, scanner->calib_table.m_Width);

        mpack_write_cstr(&writer, "height");
        mpack_write_uint(&writer, scanner->calib_table.m_Height);

        mpack_write_cstr(&writer, "mult_w");
        mpack_write_uint(&writer, scanner->calib_table.m_MultW);

        mpack_write_cstr(&writer, "mult_h");
        mpack_write_uint(&writer, scanner->calib_table.m_MultH);

        mpack_write_cstr(&writer, "time_stamp");
        mpack_write_int(&writer, scanner->calib_table.m_TimeStamp);

        mpack_write_cstr(&writer, "crc");
        mpack_write_uint(&writer, scanner->calib_table.m_CRC16);

    }mpack_finish_map(&writer);

    // finish writing
    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");
        return FALSE;
    }

    // header size
    uint32_t header_size = sizeof (uint32_t) + sizeof (uint32_t);

    // Calc trail size and data offset
    uint32_t trail_size = (body_size % 8) == 0 ? 0 : (header_size - body_size % 8);
    uint32_t data_offset = header_size + body_size + trail_size;

    // Create payload msg buffer
    uint32_t buffer_size = header_size + body_size + trail_size + scanner->calib_table.m_DataSize;
    char* buffer = calloc(buffer_size, sizeof (char));

    // Pack msg to buffer
    memcpy(&buffer[0], (char*)&body_size, 4);
    memcpy(&buffer[4], (char*)&data_offset, 4);
    memcpy(&buffer[8], body, body_size);
    memcpy(&buffer[data_offset], scanner->calib_table.m_Data, scanner->calib_table.m_DataSize);


    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "SET_CALIBRATION_DATA";
    // payload - this is the data to be sent and their size
    char* payload                       = buffer;
    uint32_t payload_size               = buffer_size;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = TRUE;    // check crc disabled
    uint8_t is_confirmation             = TRUE;    // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_write_calibration_data_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_write_calibration_data_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_write_calibration_data_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);
    // free memory of payload
    free(body);
    free(payload);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: String (*)
            // }
            // * result: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            typedef struct
            {
                char* result;
            }answer;

            if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0)
                status = TRUE;
            else
                status = FALSE;

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ",((answer*)result)->result);

        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Save Calibration Data Method
//
rfInt8 rf627_smart_save_calibration_data_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        mpack_node_t result_data = mpack_node_map_cstr(root, "result");
        uint32_t result_size = mpack_node_strlen(result_data) + 1;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->result =
                mpack_node_cstr_alloc(result_data, result_size);

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_save_calibration_data_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_save_calibration_data_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_save_calibration_data_by_service_protocol(rf627_smart_t* scanner, rfUint32 timeout)
{
    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "SAVE_CALIBRATION_DATA";
    // payload - this is the data to be sent and their size
    char* payload                       = NULL;
    uint32_t payload_size               = 0;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_save_calibration_data_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_save_calibration_data_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_save_calibration_data_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: String (*)
            // }
            // * result: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            typedef struct
            {
                char* result;
            }answer;

            if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0)
                status = TRUE;
            else
                status = FALSE;

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ",((answer*)result)->result);

        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Reboot Method
//
rfInt8 rf627_smart_reboot_device_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        mpack_node_t result_data = mpack_node_map_cstr(root, "result");
        uint32_t result_size = mpack_node_strlen(result_data) + 1;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->result =
                mpack_node_cstr_alloc(result_data, result_size);

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_reboot_device_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_reboot_device_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_reboot_device_request_to_scanner(rf627_smart_t* scanner)
{
    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "REBOOT_DEVICE";
    // payload - this is the data to be sent and their size
    char* payload                       = NULL;
    uint32_t payload_size               = 0;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = 1000;    // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_reboot_device_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_reboot_device_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_reboot_device_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: String (*)
            // }
            // * result: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            typedef struct
            {
                char* result;
            }answer;

            if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0)
                status = TRUE;
            else
                status = FALSE;

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ",((answer*)result)->result);

        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}



//
// RF627-Smart (v2.x.x)
// Reboot Method
//
rfInt8 rf627_smart_reboot_sensor_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        mpack_node_t result_data = mpack_node_map_cstr(root, "result");
        uint32_t result_size = mpack_node_strlen(result_data) + 1;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->result =
                mpack_node_cstr_alloc(result_data, result_size);

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_reboot_sensor_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_reboot_sensor_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: String (*)
        // }
        // * result: displays the result according to the response codes.
        //           On successful execution "RF_OK".
        typedef struct
        {
            char* result;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_reboot_sensor_request_to_scanner(rf627_smart_t* scanner)
{
    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "REINIT_SENSOR";
    // payload - this is the data to be sent and their size
    char* payload                       = NULL;
    uint32_t payload_size               = 0;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "blob";  // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = 1000;    // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_reboot_sensor_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_reboot_sensor_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_reboot_sensor_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: String (*)
            // }
            // * result: displays the result according to the response codes.
            //           On successful execution "RF_OK".
            typedef struct
            {
                char* result;
            }answer;

            if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0)
                status = TRUE;
            else
                status = FALSE;

            int TRACE_LEVEL = status ? TRACE_LEVEL_DEBUG : TRACE_LEVEL_WARNING;
            int TRACE_FORMAT = status ? TRACE_FORMAT_SHORT : TRACE_FORMAT_LONG;
            TRACE(TRACE_LEVEL, TRACE_FORMAT,
                  "%s%s\n",
                  "Get response to request! "
                  "Response status: ",((answer*)result)->result);

        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Send To Periphery Method
//
rfInt8 rf627_smart_send_to_periphery_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    result: String,
        //    answer:
        //    {
        //          result: String,
        //          payload: Blob,
        //    }
        // }
        // * Blob: The set of bytes that were received. If the data was not
        //         accepted, the field is missing..
        typedef struct
        {
            char* result;
            rfBool status;
            struct
            {
                char* result;
                rfBool status;

                char* payload;
                uint32_t payload_size;
            }out;
        }answer;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->status = FALSE;
        mpack_node_t root = mpack_tree_root(&tree);
        if (mpack_node_map_contains_cstr(root, "result"))
        {
            mpack_node_t result_data = mpack_node_map_cstr(root, "result");
            uint32_t result_size = mpack_node_strlen(result_data) + 1;

            ((answer*)msg->result)->result =
                    mpack_node_cstr_alloc(result_data, result_size);

            ((answer*)msg->result)->status = TRUE;
        }

        if (mpack_node_map_contains_cstr(root, "answer"))
        {
            ((answer*)msg->result)->out.status = FALSE;

            mpack_node_t answer_node = mpack_node_map_cstr(root, "answer");
            if (mpack_node_map_contains_cstr(answer_node, "result"))
            {
                mpack_node_t result_data = mpack_node_map_cstr(answer_node, "result");
                uint32_t result_size = mpack_node_strlen(result_data) + 1;

                ((answer*)msg->result)->out.result =
                        mpack_node_cstr_alloc(result_data, result_size);

                ((answer*)msg->result)->out.status = TRUE;
            }

            if (mpack_node_map_contains_cstr(answer_node, "payload"))
            {
                mpack_node_t payload_data = mpack_node_map_cstr(answer_node, "payload");
                uint32_t payload_size = mpack_node_data_len(payload_data);

                ((answer*)msg->result)->out.payload_size = payload_size;
                if (payload_size > 0)
                    ((answer*)msg->result)->out.payload = (char*)mpack_node_data_alloc(payload_data, payload_size+1);
            }
        }

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_send_to_periphery_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_send_to_periphery_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: String,
        //    answer:
        //    {
        //          result: String,
        //          payload: Blob,
        //    }
        // }
        // * Blob: The set of bytes that were received. If the data was not
        //         accepted, the field is missing..
        typedef struct
        {
            char* result;
            rfBool status;
            struct
            {
                char* result;
                rfBool status;

                char* payload;
                uint32_t payload_size;
            }out;
        }answer;

        answer* answ = msg->result;


        if (answ->status)
        {
            if (answ->out.status)
            {
                if (answ->out.payload_size > 0)
                    free(answ->out.payload);

                free(answ->out.result);
            }
            free(answ->result);
        }

        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_send_to_periphery_by_service_protocol(
        rf627_smart_t* scanner, const rfChar* device_name, rfChar* in,
        rfUint32 in_size, char** out, rfUint32* out_size,  rfUint32 timeout)
{
    // Create payload
    mpack_writer_t writer;
    rfChar* data = NULL; //< A growing array for msg.
    rfSize data_size = 0; //< Number of msg bytes.
    mpack_writer_init_growable(&writer, &data, &data_size);


    // Payload:
    // {
    //    interface: String
    //    payload: blob,
    //    wait_answer: bool,
    //    answer_timeout: number (uint32_t)
    // }
    mpack_start_map(&writer, 4);
    {
        mpack_write_cstr(&writer, "interface");
        mpack_write_cstr(&writer, device_name);

        mpack_write_cstr(&writer, "payload");
        mpack_write_bin(&writer, in, in_size);

        mpack_write_cstr(&writer, "wait_answer");
        mpack_write_bool(&writer, timeout > 0 ? TRUE : FALSE);

        mpack_write_cstr(&writer, "answer_timeout");
        mpack_write_uint(&writer, timeout*1000);
    }mpack_finish_map(&writer);

    // finish writing
    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");
        return FALSE;
    }

    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "SEND_TO_PERIPHERY";
    // payload - this is the data to be sent and their size
    char* payload                       = data;
    uint32_t payload_size               = (uint32_t)data_size;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "mpack"; // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout + 300; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_send_to_periphery_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_send_to_periphery_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_send_to_periphery_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);
    // free memory of payload
    free(payload);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: String,
            //    answer:
            //    {
            //          result: String,
            //          payload: Blob,
            //    }
            // }
            // * Blob: The set of bytes that were received. If the data was not
            //         accepted, the field is missing..
            typedef struct
            {
                char* result;
                rfBool status;
                struct
                {
                    char* result;
                    rfBool status;

                    char* payload;
                    uint32_t payload_size;
                }out;
            }answer;

            answer* answ = result;

            if (rf_strcmp(answ->result, "RF_OK") == 0)
            {
                status = TRUE;
                TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
                      "%s%s\n",
                      "Get response to request! "
                      "Response status: ",((answer*)result)->result);

                if (answ->out.status == TRUE)
                {
                    if(rf_strcmp(answ->out.result, "RF_OK") == 0)
                    {
                        (*out) = calloc(1, answ->out.payload_size);
                        *out_size = answ->out.payload_size;
                        memcpy((*out), answ->out.payload, answ->out.payload_size);
                    }
                    else
                    {
                        if (timeout > 0)
                        {
                            status = FALSE;
                            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,
                                  "%s%s\n",
                                  "Get response to request! "
                                  "Response status: ",((answer*)result)->out.result);
                        }
                    }
                }
            }
            else
            {
                status = FALSE;
                TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,
                      "%s%s\n",
                      "Get response to request! "
                      "Response status: ",((answer*)result)->result);
            }
        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}

//
// RF627-Smart (v2.x.x)
// Receive From Periphery Method
//
rfInt8 rf627_smart_receive_from_periphery_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    // Get response
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,
              "PARSING ERROR to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
              msg->cmd_name, msg->_uid, data_size);
        return status;
    }

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    result: String,
        //    payload: Blob,
        // }
        // * Blob: The set of bytes that were received. If the data was not
        //         accepted, the field is missing..
        typedef struct
        {
            char* result;
            rfBool status;

            char* payload;
            uint32_t payload_size;
        }answer;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->status = FALSE;
        mpack_node_t root = mpack_tree_root(&tree);
        if (mpack_node_map_contains_cstr(root, "result"))
        {
            mpack_node_t result_data = mpack_node_map_cstr(root, "result");
            uint32_t result_size = mpack_node_strlen(result_data) + 1;

            ((answer*)msg->result)->result =
                    mpack_node_cstr_alloc(result_data, result_size);

            ((answer*)msg->result)->status = TRUE;
        }

        if (mpack_node_map_contains_cstr(root, "payload"))
        {
            mpack_node_t payload_data = mpack_node_map_cstr(root, "payload");
            uint32_t payload_size = mpack_node_data_len(payload_data);

            ((answer*)msg->result)->payload_size = payload_size;
            if (payload_size > 0)
                ((answer*)msg->result)->payload = (char*)mpack_node_data_alloc(payload_data, payload_size+1);
        }

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return status;
}
rfInt8 rf627_smart_receive_from_periphery_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_receive_from_periphery_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    result: String,
        //    payload: Blob
        // }
        // * Blob: The set of bytes that were received. If the data was not
        //         accepted, the field is missing..
        typedef struct
        {
            char* result;
            rfBool status;

            char* payload;
            uint32_t payload_size;
        }answer;

        answer* answ = msg->result;

        if (answ->status)
        {
            if (answ->payload_size > 0)
                    free(answ->payload);
            free(answ->result);
        }

        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_receive_from_periphery_by_service_protocol(
        rf627_smart_t* scanner, const rfChar* device_name,
        rfUint16 count, char** out, rfUint32* out_size, rfUint32 timeout)
{
    // Create payload
    mpack_writer_t writer;
    rfChar* data = NULL; //< A growing array for msg.
    rfSize data_size = 0; //< Number of msg bytes.
    mpack_writer_init_growable(&writer, &data, &data_size);


    // Payload:
    // {
    //    interface: String
    //    count: uint16_t,
    //    timeout: number (uint32_t)
    // }
    mpack_start_map(&writer, 3);
    {
        mpack_write_cstr(&writer, "interface");
        mpack_write_cstr(&writer, device_name);

        mpack_write_cstr(&writer, "count");
        mpack_write_uint(&writer, count);

        mpack_write_cstr(&writer, "timeout");
        mpack_write_uint(&writer, timeout*1000);
    }mpack_finish_map(&writer);

    // finish writing
    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");
        return FALSE;
    }

    // cmd_name - this is logical port/path where data will be send
    char* cmd_name                      = "RECEIVE_FROM_PERIPHERY";
    // payload - this is the data to be sent and their size
    char* payload                       = data;
    uint32_t payload_size               = (uint32_t)data_size;
    // data_type - this is the type of packaging of the sent data
    char* data_type                     = "mpack"; // mpack, json, blob..
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = timeout + 300; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_receive_from_periphery_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_receive_from_periphery_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_receive_from_periphery_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, payload, payload_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);
    // free memory of payload
    free(payload);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    result: String,
            //    payload: Blob
            // }
            // * Blob: The set of bytes that were received. If the data was not
            //         accepted, the field is missing..
            typedef struct
            {
                char* result;
                rfBool status;

                char* payload;
                uint32_t payload_size;
            }answer;

            answer* answ = result;

            if (rf_strcmp(answ->result, "RF_OK") == 0)
            {
                status = TRUE;
                TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
                      "%s%s\n",
                      "Get response to request! "
                      "Response status: ",((answer*)result)->result);

                *out_size = answ->payload_size;
                if (*out_size > 0)
                {
                    (*out) = calloc(1, *out_size);
                    memcpy((*out), answ->payload, *out_size);
                }
            }
            else
            {
                status = FALSE;
                TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,
                      "%s%s\n",
                      "Get response to request! "
                      "Response status: ",((answer*)result)->result);
            }
        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}


//
// RF627-Smart (v2.x.x)
// Custom Command Method
//
rfInt8 rf627_smart_send_custom_command_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    RF62X_msg_t* msg = rqst_msg;
    int32_t status = FALSE;
    rfBool existing = FALSE;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "GET ANSWER to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          msg->cmd_name, msg->_uid, data_size);

    rfSize scanner_list_size = vector_count(search_history);
    for (rfUint32 i = 0; i < scanner_list_size; i++)
    {
        scanner_base_t* scanner = (scanner_base_t*)vector_get(search_history, i);
        if(scanner->type == kRF627_SMART)
            if (scanner->rf627_smart->info_by_service_protocol.
                    fact_general_serial == device_id)
                existing = TRUE;
    }

    // If scanner exist
    if (existing)
    {
        // Answer:
        // {
        //    status: Bool,
        //    payload: Blob,
        //    payload_size: Uint32,
        // }
        typedef struct
        {
            rfBool status;
            char* payload;
            uint32_t payload_size;
        }answer;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->status = TRUE;
        ((answer*)msg->result)->payload_size = data_size;
        if (data_size > 0)
        {
            ((answer*)msg->result)->payload = (char*)memory_platform.rf_calloc(data_size,1);
            memcpy(((answer*)msg->result)->payload, data, data_size);
        }

        status = TRUE;
    }

    return status;
}
rfInt8 rf627_smart_send_custom_command_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "TIMEOUT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_send_custom_command_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
          "FREE RESULT to %s command, rqst-id: %" PRIu64 ".\n",
          msg->cmd_name, msg->_uid);

    pthread_mutex_lock(((RF62X_msg_t*)rqst_msg)->result_mutex);
    if (msg->result != NULL)
    {
        // Answer:
        // {
        //    status: Bool,
        //    payload: Blob,
        //    payload_size: Uint32,
        // }
        typedef struct
        {
            rfBool status;
            char* payload;
            uint32_t payload_size;
        }answer;

        answer* answ = msg->result;

        if (answ->status)
        {
            if (answ->payload_size > 0)
                    free(answ->payload);
        }

        free(msg->result);
        msg->result = NULL;
    }
    pthread_mutex_unlock(((RF62X_msg_t*)rqst_msg)->result_mutex);

    return TRUE;
}
rfBool rf627_smart_send_custom_command(
        rf627_smart_t* scanner, const rfChar* cmd_name, const rfChar* data_type,
        rfChar* payload, uint32_t payload_size, rfChar** out, rfUint32* out_size)
{
    uint8_t is_check_crc                = FALSE;   // check crc disabled
    uint8_t is_confirmation             = FALSE;   // confirmation disabled
    uint8_t is_one_answ                 = TRUE;    // wait only one answer
    uint32_t waiting_time               = 100; // ms
    uint32_t resends                    = is_confirmation ? 3 : 0;
    // callbacks for request
    RF62X_answ_callback answ_clb        = rf627_smart_send_custom_command_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_send_custom_command_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_send_custom_command_free_result_callback;

    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            is_check_crc = p->is_check_crc;
            is_confirmation = p->is_confirmation;
            is_one_answ = p->is_one_answ;
            waiting_time = p->waiting_time;
            resends = is_confirmation ? p->resends_count : 0;
            break;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);

    // Create request message
    RF62X_msg_t* msg = RF62X_create_rqst_msg((rfChar*)cmd_name, payload, payload_size, (rfChar*)data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time, resends,
                                             answ_clb, timeout_clb, free_clb);

    rfBool status = FALSE;
    // Send msg
    if (RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,  "%s", "Request were sent.\n");

        // try to find answer to rqst
        pthread_mutex_lock(msg->result_mutex);
        void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
        if (result != NULL)
        {
            // Answer:
            // {
            //    status: Bool,
            //    payload: Blob,
            //    payload_size: Uint32,
            // }
            typedef struct
            {
                rfBool status;
                char* payload;
                uint32_t payload_size;
            }answer;

            answer* answ = result;

            if (answ->status == TRUE)
            {
                status = TRUE;
                TRACE(TRACE_LEVEL_DEBUG, TRACE_FORMAT_SHORT,
                      "%s%s\n",
                      "Get response to request! "
                      "Response status: ", "OK");

                *out_size = answ->payload_size;
                if (*out_size > 0)
                {
                    (*out) = calloc(1, *out_size);
                    memcpy((*out), answ->payload, *out_size);
                }
            }
            else
            {
                status = FALSE;
                TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,
                      "%s%s\n",
                      "Get response to request! "
                      "Response status: ","ERROR");
            }
        }else
        {
            TRACE(TRACE_LEVEL_WARNING, TRACE_FORMAT_LONG,  "%s", "No response to request!\n");
        }
        pthread_mutex_unlock(msg->result_mutex);
    }
    else
    {
        TRACE(TRACE_LEVEL_ERROR, TRACE_FORMAT_LONG,  "%s", "No data has been sent.\n");
    }

    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return status;
}








rf627_smart_calib_table_t* rf627_smart_get_calibration_table(rf627_smart_t* scanner)
{
    rf627_smart_calib_table_t* _calib_table = (rf627_smart_calib_table_t*)calloc(1, sizeof (rf627_smart_calib_table_t));

    _calib_table->m_Type = scanner->calib_table.m_Type;
    _calib_table->m_CRC16 = scanner->calib_table.m_CRC16;
    _calib_table->m_Serial = scanner->calib_table.m_Serial;
    _calib_table->m_DataRowLength = scanner->calib_table.m_DataRowLength;
    _calib_table->m_Width = scanner->calib_table.m_Width;
    _calib_table->m_Height = scanner->calib_table.m_Height;
    _calib_table->m_MultW = scanner->calib_table.m_MultW;
    _calib_table->m_MultH = scanner->calib_table.m_MultH;
    _calib_table->m_TimeStamp = scanner->calib_table.m_TimeStamp;

    _calib_table->m_DataSize = scanner->calib_table.m_DataSize;
    _calib_table->m_Data = calloc(_calib_table->m_DataSize, sizeof (uint8_t));
    memcpy(_calib_table->m_Data, scanner->calib_table.m_Data, _calib_table->m_DataSize * sizeof (uint8_t));

    return _calib_table;
}

rfBool rf627_smart_set_calibration_table(rf627_smart_t* scanner, rf627_smart_calib_table_t* table)
{
    scanner->calib_table.m_Type = table->m_Type;
    scanner->calib_table.m_CRC16 = table->m_CRC16;
    scanner->calib_table.m_Serial = table->m_Serial;
    scanner->calib_table.m_DataRowLength = table->m_DataRowLength;
    scanner->calib_table.m_Width = table->m_Width;
    scanner->calib_table.m_Height = table->m_Height;
    scanner->calib_table.m_MultW = table->m_MultW;
    scanner->calib_table.m_MultH = table->m_MultH;
    scanner->calib_table.m_TimeStamp = table->m_TimeStamp;

    scanner->calib_table.m_DataSize = table->m_DataSize;
    scanner->calib_table.m_Data = calloc(scanner->calib_table.m_DataSize, sizeof (uint8_t));
    memcpy(scanner->calib_table.m_Data, table->m_Data, scanner->calib_table.m_DataSize * sizeof (uint8_t));

    return TRUE;
}

rfBool rf627_smart_add_protocol_settings_for_cmd(
        rf627_smart_t *scanner, const char *cmd_name,
        rfUint8 crc_enabled, rfUint8 confirm_enabled, rfUint8 one_answ,
        rfUint32 waiting_time, rfUint32 resends_count)
{
    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            p->is_check_crc = crc_enabled;
            p->is_confirmation = confirm_enabled;
            p->is_one_answ = one_answ;
            p->waiting_time = waiting_time;
            p->resends_count = resends_count;
            pthread_mutex_unlock(&scanner->protocol_settings_mutex);
            return TRUE;
        }
    }

    p = memory_platform.rf_calloc(1, sizeof (rf627_smart_protocol_cmd_settings_t));
    p->cmd_name = memory_platform.rf_calloc(1, rf_strlen(cmd_name) + 1);
    memcpy(p->cmd_name, cmd_name, rf_strlen(cmd_name));
    p->is_check_crc = crc_enabled;
    p->is_confirmation = confirm_enabled;
    p->is_one_answ = one_answ;
    p->waiting_time = waiting_time;
    p->resends_count = resends_count;
    vector_add(scanner->protocol_settings_list, p);
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);
    return TRUE;
}

rfBool rf627_smart_remove_protocol_settings_for_cmd(
        rf627_smart_t *scanner, const char *cmd_name)
{
    rf627_smart_protocol_cmd_settings_t* p = NULL;
    pthread_mutex_lock(&scanner->protocol_settings_mutex);
    for(rfSize i = 0; i < vector_count(scanner->protocol_settings_list); i++)
    {
        p = vector_get(scanner->protocol_settings_list, i);
        if (rf_strcmp(p->cmd_name, cmd_name) == 0)
        {
            memory_platform.rf_free(p->cmd_name);
            memory_platform.rf_free(p);

            vector_delete(scanner->protocol_settings_list, i);
            pthread_mutex_unlock(&scanner->protocol_settings_mutex);
            return TRUE;
        }
    }
    pthread_mutex_unlock(&scanner->protocol_settings_mutex);
    return FALSE;
}

char* generate_config_string(
        uint32_t host_device_uid, char* host_ip_addr, char* dst_ip_addr,
        uint32_t host_udp_port, uint32_t dst_udp_port, uint32_t socket_timeout,
        uint32_t max_packet_size, uint32_t max_data_size)
{
    char* config = calloc(1024, sizeof (char));

    sprintf(config,
            "--host_device_uid %d "
            "--host_ip_addr %s "
            "--dst_ip_addr %s "
            "--host_udp_port %d "
            "--dst_udp_port %d "
            "--socket_timeout %d "
            "--max_packet_size %d "
            "--max_data_size %d",
            host_device_uid, host_ip_addr, dst_ip_addr, host_udp_port, dst_udp_port,
            socket_timeout, max_packet_size, max_data_size);

    return config;
}

