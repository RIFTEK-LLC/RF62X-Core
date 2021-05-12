#include "rf62X_sdk.h"
#include "iostream_platform.h"
#include "netwok_platform.h"
#include "memory_platform.h"
#include "custom_string.h"
#include "RF62Xchannel.h"
#include "RF62Xtypes.h"
#include <stdarg.h>
#include <stdio.h>

#include <mpack/mpack.h>
#include "utils.h"

#include<time.h>
void delay(unsigned int mseconds)
{
    clock_t goal = mseconds + clock() * (1000.0 /CLOCKS_PER_SEC);
    while (goal > clock() * (1000.0 /CLOCKS_PER_SEC));
}

/**
 * @brief generate_config_string - generate config string
 * @return config string.
 */
char* generate_config_string(
        uint32_t host_device_uid, char* host_ip_addr, char* dst_ip_addr,
        uint32_t host_udp_port, uint32_t dst_udp_port, uint32_t socket_timeout,
        uint32_t max_packet_size, uint32_t max_data_size);

int answ_count = 0;
vector_t *search_result = NULL;



rf627_smart_t* rf627_smart_create_from_hello_msg(char* data, rfUint32 data_size)
{
    rf627_smart_t* rf627_smart = memory_platform.rf_calloc(1, sizeof (rf627_smart_t));
    memset(rf627_smart, 0, sizeof (rf627_smart_t));

    vector_init(&rf627_smart->params_list);

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
                mpack_node_uint(mpack_node_map_cstr(root, "user_streams_udpEnabled"));
    }

    // The format of the transmitted profiles.
    if (mpack_node_map_contains_cstr(root, "user_streams_format"))
    {
        rf627_smart->info_by_service_protocol.user_streams_format =
                mpack_node_uint(mpack_node_map_cstr(root, "user_streams_format"));
    }

    mpack_tree_destroy(&tree);
    return rf627_smart;

}
void rf627_smart_free(rf627_smart_t* scanner)
{
    RF62X_channel_cleanup(&scanner->channel);
    network_platform.network_methods.close_socket(scanner->m_data_sock);

    while (vector_count(scanner->params_list) > 0)
    {
        parameter_t* p = vector_get(scanner->params_list, vector_count(scanner->params_list)-1);
        free_parameter(p, kRF627_SMART);

        vector_delete(scanner->params_list, vector_count(scanner->params_list)-1);
    }

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
    uint32_t max_packet_size = 65535;
    uint32_t max_data_size = 20000000;

    char* config = generate_config_string(
                    host_device_uid,
                    "127.0.0.1",//scanner->info_by_service_protocol.user_network_hostIP,
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
                        scanner->m_data_sock, 1000);
            //recv_addr.sin_family = RF_AF_INET;
            recv_port = scanner->info_by_service_protocol.user_network_hostPort;

            //recv_addr.sin_addr = RF_INADDR_ANY;
            ip_string_to_uint32("127.0.0.1",/*scanner->info_by_service_protocol.user_network_hostIP*/&recv_ip_addr);

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
                        if (zero_points == 0 && z > 0 && x != 0)
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
            if (rf_strcmp(p->base.type, parameter_value_types[PVT_STRING]) == 0)
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
            else if (rf_strcmp(p->base.type, parameter_value_types[PVT_INT]) == 0)
            {
                p->val_int32->value = param->val_int32->value;
                p->is_changed = TRUE;
                return TRUE;
            }
            else if (rf_strcmp(p->base.type, parameter_value_types[PVT_INT64]) == 0)
            {
                p->val_int64->value = param->val_int64->value;
                p->is_changed = TRUE;
                return TRUE;
            }
            else if (rf_strcmp(p->base.type, parameter_value_types[PVT_UINT]) == 0)
            {
                p->val_uint32->value = param->val_uint32->value;
                p->is_changed = TRUE;
                return TRUE;
            }
            else if (rf_strcmp(p->base.type, parameter_value_types[PVT_UINT64]) == 0)
            {
                p->val_uint64->value = param->val_uint64->value;
                p->is_changed = TRUE;
                return TRUE;
            }
            else if (rf_strcmp(p->base.type, parameter_value_types[PVT_FLOAT]) == 0)
            {
                p->val_flt->value = param->val_flt->value;
                p->is_changed = TRUE;
                return TRUE;
            }
            else if (rf_strcmp(p->base.type, parameter_value_types[PVT_DOUBLE]) == 0)
            {
                p->val_dbl->value = param->val_dbl->value;
                p->is_changed = TRUE;
                return TRUE;
            }else if (rf_strcmp(p->base.type, parameter_value_types[PVT_ARRAY_UINT32]) == 0)
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




rfInt8 rf627_smart_get_hello_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    TRACE(TRACE_LEVEL_DEBUG, "+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
          ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = FALSE;
    rfBool existing = FALSE;

    for (rfUint32 i = 0; i < vector_count(search_result); i++)
    {
        if(((scanner_base_t*)vector_get(search_result, i))->type == kRF627_SMART)
        {
            uint32_t serial = ((scanner_base_t*)vector_get(search_result, i))->rf627_smart->info_by_service_protocol.fact_general_serial;
            if (serial == device_id)
            {
                existing = TRUE;
            }
        }
    }

    if (!existing)
    {
        TRACE(TRACE_LEVEL_DEBUG, "Found scanner %d\n", device_id);

        scanner_base_t* rf627 =
                memory_platform.rf_calloc(1, sizeof(scanner_base_t));

        rf627->type = kRF627_SMART;
        rf627->rf627_smart = rf627_smart_create_from_hello_msg(
                    data, data_size);
        vector_add(search_result, rf627);

        RF62X_msg_t* msg = rqst_msg;
        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (uint32_t));
        }
        *(uint32_t*)msg->result = (uint32_t)vector_count(search_result);

        status = TRUE;
    }

    return status;

}
rfInt8 rf627_smart_get_hello_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_get_hello_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    if (msg->result != NULL)
    {
        free(msg->result);
        msg->result = NULL;
    }

    return TRUE;
}
uint8_t rf627_smart_search_by_service_protocol(vector_t *scanner_list, rfUint32 ip_addr, rfUint32 timeout)
{
    // Если изменился указатель на старый результат поиска, значит поиск был
    // запущен повторно. Поэтому неоходимо очистить память, выделенную во
    // время предыдущего поиска.
    if (search_result != scanner_list && search_result != NULL)
    {
        while (vector_count(search_result) > 0) {
            vector_delete(search_result, vector_count(search_result)-1);
        }
        free (search_result); search_result = NULL;
    }
    search_result = scanner_list;

    uint32_t host_device_uid = 777;
    char* host_ip_addr = NULL;
    uint32_to_ip_string(ip_addr, &host_ip_addr);
    char* dst_ip_addr = NULL;
    uint32_to_ip_string(((uint32_t)(ip_addr) | 0xFF), &dst_ip_addr);
    uint32_t host_udp_port = 0;
    uint32_t dst_udp_port = 50011;
    uint32_t socket_timeout = 100;
    uint32_t max_packet_size = 65535;
    uint32_t max_data_size = 20000000;

    char* config = generate_config_string(
                    host_device_uid, host_ip_addr, dst_ip_addr,
                    host_udp_port, dst_udp_port, socket_timeout,
                    max_packet_size, max_data_size);

    RF62X_channel_t channel;
    rfBool is_inited = RF62X_channel_init(&channel, config);

    free(host_ip_addr); free(dst_ip_addr); free(config);

    if (is_inited == TRUE)
    {
        char* cmd_name                      = "GET_HELLO";
        char* data                          = NULL;
        uint32_t data_size                  = 0;
        char* data_type                     = "blob";
        uint8_t is_check_crc                = FALSE;
        uint8_t is_confirmation             = FALSE;
        uint8_t is_one_answ                 = FALSE;
        uint32_t waiting_time               = timeout;
        RF62X_answ_callback answ_clb        = rf627_smart_get_hello_callback;
        RF62X_timeout_callback timeout_clb  = rf627_smart_get_hello_timeout_callback;
        RF62X_free_callback free_clb        = rf627_smart_get_hello_free_result_callback;

        RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, data, data_size, data_type,
                                                 is_check_crc, is_confirmation, is_one_answ,
                                                 waiting_time,
                                                 answ_clb, timeout_clb, free_clb);

        // Send test msg
        if (!RF62X_channel_send_msg(&channel, msg))
        {
            TRACE(TRACE_LEVEL_ERROR, "%s", "No data has been sent.\n");
        }
        else
        {
            TRACE(TRACE_LEVEL_DEBUG, "%s", "Requests were sent.\n");
        }

        uint8_t scanner_count = 0;
        void* result = RF62X_find_result_to_rqst_msg(&channel, msg, waiting_time);
        if (result != NULL)
        {
            scanner_count = *(uint8_t*)result;
        }

        // Cleanup test msg
        RF62X_cleanup_msg(msg);
        free(msg); msg = NULL;
        RF62X_channel_cleanup(&channel);
        return scanner_count;
    }else
    {
        TRACE(TRACE_LEVEL_WARNING, "%s - smart channel not initialized", config);
        RF62X_channel_cleanup(&channel);
    }
    return 0;

}

rfInt8 rf627_smart_check_connection_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    TRACE(TRACE_LEVEL_DEBUG, "+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = FALSE;
    rfBool existing = FALSE;

    // check connection
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        return status;
    }

    for (rfUint32 i = 0; i < vector_count(search_result); i++)
    {
        if(((scanner_base_t*)vector_get(search_result, i))->type == kRF627_SMART)
        {
            uint32_t serial = ((scanner_base_t*)vector_get(search_result, i))->rf627_smart->info_by_service_protocol.fact_general_serial;
            if (serial == device_id)
                existing = TRUE;
        }
    }

    if (existing)
    {
        RF62X_msg_t* msg = rqst_msg;
        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (uint32_t));
        }
        *(uint32_t*)msg->result = TRUE;

        status = TRUE;
    }

    mpack_tree_destroy(&tree);
    return TRUE;
}
rfInt8 rf627_smart_check_connection_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_check_connection_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    if (msg->result != NULL)
    {
        free(msg->result);
        msg->result = NULL;
    }

    return TRUE;
}
rfBool rf627_smart_check_connection_by_service_protocol(rf627_smart_t* scanner, rfUint32 timeout)
{
    char* cmd_name                      = "GET_HELLO";
    char* data                          = NULL;
    uint32_t data_size                  = 0;
    char* data_type                     = "blob";
    uint8_t is_check_crc                = FALSE;
    uint8_t is_confirmation             = FALSE;
    uint8_t is_one_answ                 = TRUE;
    uint32_t waiting_time               = timeout;
    RF62X_answ_callback answ_clb        = rf627_smart_check_connection_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_check_connection_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_check_connection_free_result_callback;

    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, data, data_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time,
                                             answ_clb, timeout_clb, free_clb);

    // Send test msg
    if (!RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_ERROR, "%s", "No data has been sent.\n");
    }
    else
    {
        TRACE(TRACE_LEVEL_DEBUG, "%s", "Requests were sent.\n");
    }


    uint32_t is_connected = 0;
    void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
    if (result != NULL)
    {
        is_connected = *(uint32_t*)result;
    }

    // Cleanup test msg
    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;

    if (is_connected)
        return TRUE;
    else return FALSE;
}

rfInt8 rf627_smart_read_params_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    TRACE(TRACE_LEVEL_DEBUG, "+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = FALSE;
    rfBool existing = FALSE;

    int index = -1;
    for (rfUint32 i = 0; i < vector_count(search_result); i++)
    {
        if(((scanner_base_t*)vector_get(search_result, i))->type == kRF627_SMART)
        {
            uint32_t serial = ((scanner_base_t*)vector_get(search_result, i))->rf627_smart->info_by_service_protocol.fact_general_serial;
            if (serial == device_id)
            {
                existing = TRUE;
                index = i;
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


            if(rf_strcmp(parameter_value_types[PVT_UINT], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_UINT64], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_INT], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_INT64], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_FLOAT], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_DOUBLE], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_UINT32], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_UINT64], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_INT32], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_INT64], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_FLT], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_DBL], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_STRING], p->base.type) == 0)
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

            vector_add(((scanner_base_t*)vector_get(search_result, index))->rf627_smart->params_list, p);
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

            if(rf_strcmp(parameter_value_types[PVT_UINT], p->base.type) == 0)
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

            }else if(rf_strcmp(parameter_value_types[PVT_UINT64], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_INT], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_INT64], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_FLOAT], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_DOUBLE], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_UINT32], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_UINT64], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_INT32], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_INT64], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_FLT], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_DBL], p->base.type) == 0)
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
            }else if(rf_strcmp(parameter_value_types[PVT_STRING], p->base.type) == 0)
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

            vector_add(((scanner_base_t*)vector_get(search_result, index))->rf627_smart->params_list, p);
        }

        mpack_tree_destroy(&tree);

        RF62X_msg_t* msg = rqst_msg;
        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (uint32_t));
        }
        *(uint32_t*)msg->result = TRUE;

        status = TRUE;
    }

    return true;
}
rfInt8 rf627_smart_read_params_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_read_params_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    if (msg->result != NULL)
    {
        free(msg->result);
        msg->result = NULL;
    }

    return TRUE;
}
rfBool rf627_smart_read_params_from_scanner(rf627_smart_t* scanner, rfUint32 timeout)
{

    char* cmd_name                      = "GET_PARAMS_DESCRIPTION";
    char* data                          = NULL;
    uint32_t data_size                  = 0;
    char* data_type                     = "blob";
    uint8_t is_check_crc                = FALSE;
    uint8_t is_confirmation             = FALSE;
    uint8_t is_one_answ                 = TRUE;
    uint32_t waiting_time               = timeout;
    RF62X_answ_callback answ_clb        = rf627_smart_read_params_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_read_params_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_read_params_free_result_callback;

    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, data, data_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time,
                                             answ_clb, timeout_clb, free_clb);

    // Send test msg
    if (!RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_ERROR, "%s", "No data has been sent.\n");
    }
    else
    {
        TRACE(TRACE_LEVEL_DEBUG, "%s", "Requests were sent.\n");
    }


    uint8_t is_read = 0;
    void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
    if (result != NULL)
    {
        is_read = *(uint8_t*)result;

        // Cleanup test msg
        RF62X_cleanup_msg(msg);
        free(msg); msg = NULL;

        if (is_read)
            return TRUE;
        else
        {
            TRACE(TRACE_LEVEL_ERROR, "%s", "Parameters parsing error.\n");
            return FALSE;
        }
    }else
    {
        TRACE(TRACE_LEVEL_WARNING, "%s", "No response to GET_PARAMS_DESCRIPTION request!\n");
    }

    // Cleanup test msg
    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;
    return FALSE;


}

rfInt8 rf627_smart_write_params_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    TRACE(TRACE_LEVEL_DEBUG, "+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    return TRUE;
}
rfInt8 rf627_smart_write_params_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_write_params_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    if (msg->result != NULL)
    {
        free(msg->result);
        msg->result = NULL;
    }

    return TRUE;
}
rfBool rf627_smart_write_params_to_scanner(rf627_smart_t* scanner, rfUint32 timeout)
{
    int count = 0;
    for(rfSize i = 0; i < vector_count(scanner->params_list); i++)
    {
        parameter_t* p = vector_get(scanner->params_list, i);
        if (p->is_changed)
        {
            count++;
        }
    }

    if (count > 0)
    {
        // Create FULL DATA packet for measurement SIZE of data packet
        mpack_writer_t writer;
        char* send_packet = NULL;
        size_t bytes = 0;				///< Number of msg bytes.
        mpack_writer_init_growable(&writer, &send_packet, &bytes);

        // write the example on the msgpack homepage
        mpack_start_map(&writer, count);
        {
            for(rfSize i = 0; i < vector_count(scanner->params_list); i++)
            {
                parameter_t* p = vector_get(scanner->params_list, i);
                if (p->is_changed)
                {
                    // Идентификатор устройства, отправившего сообщения
                    mpack_write_cstr(&writer, p->base.name);
                    if(rf_strcmp(parameter_value_types[PVT_UINT], p->base.type) == 0)
                    {
                        mpack_write_u32(&writer, p->val_uint32->value);
                    }else if(rf_strcmp(parameter_value_types[PVT_UINT64], p->base.type) == 0)
                    {
                       mpack_write_u64(&writer, p->val_uint64->value);
                    }else if(rf_strcmp(parameter_value_types[PVT_INT], p->base.type) == 0)
                    {
                       mpack_write_i32(&writer, p->val_int32->value);
                    }else if(rf_strcmp(parameter_value_types[PVT_INT64], p->base.type) == 0)
                    {
                        mpack_write_i64(&writer, p->val_int64->value);
                    }else if(rf_strcmp(parameter_value_types[PVT_FLOAT], p->base.type) == 0)
                    {
                       mpack_write_float(&writer, p->val_flt->value);
                    }else if(rf_strcmp(parameter_value_types[PVT_DOUBLE], p->base.type) == 0)
                    {
                        mpack_write_double(&writer, p->val_dbl->value);
                    }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_UINT32], p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_uint32->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_uint32->count; ii++)
                                mpack_write_u32(&writer, p->arr_uint32->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_UINT64], p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_uint64->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_uint64->count; ii++)
                                mpack_write_u64(&writer, p->arr_uint64->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_INT32], p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_int32->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_int32->count; ii++)
                                mpack_write_i32(&writer, p->arr_int32->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_INT64], p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_int64->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_int64->count; ii++)
                                mpack_write_i64(&writer, p->arr_int64->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_FLT], p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_flt->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_flt->count; ii++)
                                mpack_write_float(&writer, p->arr_flt->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp(parameter_value_types[PVT_ARRAY_DBL], p->base.type) == 0)
                    {
                        mpack_start_array(&writer, p->arr_dbl->count);
                        {
                            for (rfSize ii = 0; ii < p->arr_dbl->count; ii++)
                                mpack_write_double(&writer, p->arr_dbl->value[ii]);
                        }mpack_finish_array(&writer);
                    }else if(rf_strcmp(parameter_value_types[PVT_STRING], p->base.type) == 0)
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


        char* cmd_name                      = "SET_PARAMETERS";
        char* data                          = send_packet;
        uint32_t data_size                  = (rfUint32)bytes;
        char* data_type                     = "mpack";
        uint8_t is_check_crc                = FALSE;
        uint8_t is_confirmation             = FALSE;
        uint8_t is_one_answ                 = TRUE;
        uint32_t waiting_time               = timeout;
        RF62X_answ_callback answ_clb        = rf627_smart_write_params_callback;
        RF62X_timeout_callback timeout_clb  = rf627_smart_write_params_timeout_callback;
        RF62X_free_callback free_clb        = rf627_smart_write_params_free_result_callback;

        RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, data, data_size, data_type,
                                                 is_check_crc, is_confirmation, is_one_answ,
                                                 waiting_time,
                                                 answ_clb, timeout_clb, free_clb);

        // Send test msg
        if (!RF62X_channel_send_msg(&scanner->channel, msg))
        {
            TRACE(TRACE_LEVEL_ERROR, "%s", "No data has been sent.\n");
        }
        else
        {
            TRACE(TRACE_LEVEL_DEBUG, "%s", "Requests were sent.\n");
        }

        // Cleanup test msg
        RF62X_cleanup_msg(msg);
        free(msg); msg = NULL;
        free(send_packet);

        return TRUE;
    }

    return FALSE;
}

rfInt8 rf627_smart_get_frame_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    TRACE(TRACE_LEVEL_DEBUG, "+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = FALSE;

    int index = -1;
    for (rfUint32 i = 0; i < vector_count(search_result); i++)
    {
        if(((scanner_base_t*)vector_get(search_result, i))->type == kRF627_SMART)
        {
            if (((scanner_base_t*)vector_get(search_result, i))->rf627_smart->info_by_service_protocol.fact_general_serial == device_id)
            {
                index = i;
                break;
            }
        }
    }

    if (index != -1)
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

        RF62X_msg_t* msg = rqst_msg;
        msg->result = calloc(1, sizeof (rf627_smart_frame_t));
        rf627_smart_frame_t* frame = msg->result;

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

        status = TRUE;

        mpack_tree_destroy(&tree);
        return true;
    }

    return false;
}
rfInt8 rf627_smart_get_frame_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_get_frame_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    if (msg->result != NULL)
    {
        rf627_smart_frame_t* frame = msg->result;
        if (frame->data != NULL && frame->data_size > 0)
        {
            free(frame->data);
            frame->data_size = 0;
        }
        free(msg->result);
        msg->result = NULL;
    }

    return TRUE;
}
rf627_smart_frame_t* rf627_smart_get_frame(rf627_smart_t* scanner, rfUint32 timeout)
{
    char* cmd_name                      = "GET_FRAME";
    char* data                          = NULL;
    uint32_t data_size                  = 0;
    char* data_type                     = "blob";
    uint8_t is_check_crc                = FALSE;
    uint8_t is_confirmation             = FALSE;
    uint8_t is_one_answ                 = TRUE;
    uint32_t waiting_time               = timeout;
    RF62X_answ_callback answ_clb        = rf627_smart_get_frame_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_get_frame_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_get_frame_free_result_callback;


    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, data, data_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time,
                                             answ_clb, timeout_clb, free_clb);

    // Send test msg
    if (!RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_ERROR, "%s", "No data has been sent.\n");
    }
    else
    {
        TRACE(TRACE_LEVEL_DEBUG, "%s", "Requests were sent.\n");
    }


    rf627_smart_frame_t* frame = NULL;
    rf627_smart_frame_t* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
    if (result != NULL)
    {
        frame = calloc(1, sizeof (rf627_smart_frame_t));
        frame->data_size = result->data_size;
        frame->data = calloc(1, frame->data_size);
        memcpy(frame->data, (char*)result->data, frame->data_size);

        frame->user_roi_active = result->user_roi_active;

        frame->user_roi_enabled = result->user_roi_enabled;
        frame->user_roi_pos = result->user_roi_pos;
        frame->user_roi_size = result->user_roi_size;
    }else
    {
        TRACE(TRACE_LEVEL_WARNING, "%s", "No response to GET_FRAME request!\n");
    }

    // Cleanup test msg
    RF62X_cleanup_msg(msg);
    free(msg); msg = NULL;

    return frame;
}


rfInt8 rf627_smart_get_dumps_profiles_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    TRACE(TRACE_LEVEL_DEBUG, "+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = FALSE;
    rfBool existing = FALSE;

    for (rfUint32 i = 0; i < vector_count(search_result); i++)
    {
        if(((scanner_base_t*)vector_get(search_result, i))->type == kRF627_SMART)
        {
            uint32_t serial = ((scanner_base_t*)vector_get(search_result, i))->rf627_smart->info_by_service_protocol.fact_general_serial;
            if (serial == device_id)
                existing = TRUE;
        }
    }

    if (existing)
    {
        RF62X_msg_t* msg = rqst_msg;
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

    TRACE(TRACE_LEVEL_DEBUG, "- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_get_dumps_profiles_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

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

    return TRUE;
}
rfBool rf627_smart_get_dumps_profiles_by_service_protocol(
        rf627_smart_t* scanner, uint32_t index, uint32_t count,  rfUint32 timeout,
        rf627_profile2D_t** profile_array, uint32_t* array_count, uint32_t dump_unit_size)
{
    // Create payload
    mpack_writer_t writer;
    char* payload = NULL;
    size_t bytes = 0;				///< Number of msg bytes.
    mpack_writer_init_growable(&writer, &payload, &bytes);

    // Идентификатор сообщения для подтверждения
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

    char* cmd_name                      = "GET_DUMP_DATA";
    char* data                          = payload;
    uint32_t data_size                  = (rfUint32)bytes;
    char* data_type                     = "mpack";
    uint8_t is_check_crc                = FALSE;
    uint8_t is_confirmation             = TRUE;
    uint8_t is_one_answ                 = TRUE;
    uint32_t waiting_time               = timeout;
    RF62X_answ_callback answ_clb        = rf627_smart_get_dumps_profiles_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_get_dumps_profiles_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_get_dumps_profiles_free_result_callback;

    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, data, data_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time,
                                             answ_clb, timeout_clb, free_clb);

    free(payload);

    // Send test msg
    if (!RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_ERROR, "%s", "No data has been sent.\n");
    }
    else
    {
        TRACE(TRACE_LEVEL_DEBUG, "%s", "Requests were sent.\n");
    }

    void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
    if (result != NULL)
    {
        typedef struct
        {
            char* data;
            uint32_t data_size;
        }answer;

        *array_count = ((answer*)result)->data_size / dump_unit_size;
        *profile_array = memory_platform.rf_calloc(*array_count, sizeof (rf627_profile2D_t));

        for (uint32_t i = 0; i < *array_count; i++)
        {
            (*profile_array)[i].rf627smart_profile2D =
                    memory_platform.rf_calloc(1, sizeof(rf627_smart_profile2D_t));

            (*profile_array)[i].type = kRF627_SMART;

            rf627_old_stream_msg_t header_from_msg = rf627_protocol_old_unpack_header_msg_from_profile_packet((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])));

            (*profile_array)[i].rf627smart_profile2D->header.data_type = header_from_msg.data_type;
            (*profile_array)[i].rf627smart_profile2D->header.flags = header_from_msg.flags;
            (*profile_array)[i].rf627smart_profile2D->header.device_type = header_from_msg.device_type;
            (*profile_array)[i].rf627smart_profile2D->header.serial_number = header_from_msg.serial_number;
            (*profile_array)[i].rf627smart_profile2D->header.system_time = header_from_msg.system_time;

            (*profile_array)[i].rf627smart_profile2D->header.proto_version_major = header_from_msg.proto_version_major;
            (*profile_array)[i].rf627smart_profile2D->header.proto_version_minor = header_from_msg.proto_version_minor;
            (*profile_array)[i].rf627smart_profile2D->header.hardware_params_offset = header_from_msg.hardware_params_offset;
            (*profile_array)[i].rf627smart_profile2D->header.data_offset = header_from_msg.data_offset;
            (*profile_array)[i].rf627smart_profile2D->header.packet_count = header_from_msg.packet_count;
            (*profile_array)[i].rf627smart_profile2D->header.measure_count = header_from_msg.measure_count;

            (*profile_array)[i].rf627smart_profile2D->header.zmr = header_from_msg.zmr;
            (*profile_array)[i].rf627smart_profile2D->header.xemr = header_from_msg.xemr;
            (*profile_array)[i].rf627smart_profile2D->header.discrete_value = header_from_msg.discrete_value;

            (*profile_array)[i].rf627smart_profile2D->header.exposure_time = header_from_msg.exposure_time;
            (*profile_array)[i].rf627smart_profile2D->header.laser_value = header_from_msg.laser_value;
            (*profile_array)[i].rf627smart_profile2D->header.step_count = header_from_msg.step_count;
            (*profile_array)[i].rf627smart_profile2D->header.dir = header_from_msg.dir;
            (*profile_array)[i].rf627smart_profile2D->header.payload_size = header_from_msg.payload_size;
            (*profile_array)[i].rf627smart_profile2D->header.bytes_per_point = header_from_msg.bytes_per_point;

            if((*profile_array)[i].rf627smart_profile2D->header.serial_number == scanner->info_by_service_protocol.fact_general_serial)
            {
                rfInt16 x;
                rfUint16 z;

                rfUint32 pt_count;
                switch ((*profile_array)[i].rf627smart_profile2D->header.data_type)
                {
                case DTY_PixelsNormal:
                    pt_count = (*profile_array)[i].rf627smart_profile2D->header.payload_size / (*profile_array)[i].rf627smart_profile2D->header.bytes_per_point;
                    (*profile_array)[i].rf627smart_profile2D->pixels_format.pixels_count = 0;
                    (*profile_array)[i].rf627smart_profile2D->pixels_format.pixels =
                            memory_platform.rf_calloc(pt_count, sizeof (rfUint16));
                    if ((*profile_array)[i].rf627smart_profile2D->header.flags & 0x01){
                        (*profile_array)[i].rf627smart_profile2D->intensity_count = 0;
                        (*profile_array)[i].rf627smart_profile2D->intensity =
                                memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                    }
                    break;
                case DTY_ProfileNormal:
                    pt_count = (*profile_array)[i].rf627smart_profile2D->header.payload_size / (*profile_array)[i].rf627smart_profile2D->header.bytes_per_point;
                    (*profile_array)[i].rf627smart_profile2D->profile_format.points_count = 0;
                    (*profile_array)[i].rf627smart_profile2D->profile_format.points =
                            memory_platform.rf_calloc(pt_count, sizeof (rf627_old_point2D_t));
                    if ((*profile_array)[i].rf627smart_profile2D->header.flags & 0x01){
                        (*profile_array)[i].rf627smart_profile2D->intensity_count = 0;
                        (*profile_array)[i].rf627smart_profile2D->intensity =
                                memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                    }
                    break;
                case DTY_PixelsInterpolated:
                    pt_count = (*profile_array)[i].rf627smart_profile2D->header.payload_size / (*profile_array)[i].rf627smart_profile2D->header.bytes_per_point;
                    (*profile_array)[i].rf627smart_profile2D->pixels_format.pixels_count = 0;
                    (*profile_array)[i].rf627smart_profile2D->pixels_format.pixels =
                            memory_platform.rf_calloc(pt_count, sizeof (rfUint16));
                    if ((*profile_array)[i].rf627smart_profile2D->header.flags & 0x01){
                        (*profile_array)[i].rf627smart_profile2D->intensity_count = 0;
                        (*profile_array)[i].rf627smart_profile2D->intensity =
                                memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                    }
                    break;
                case DTY_ProfileInterpolated:
                    pt_count = (*profile_array)[i].rf627smart_profile2D->header.payload_size / (*profile_array)[i].rf627smart_profile2D->header.bytes_per_point;
                    (*profile_array)[i].rf627smart_profile2D->profile_format.points_count = 0;
                    (*profile_array)[i].rf627smart_profile2D->profile_format.points =
                            memory_platform.rf_calloc(pt_count, sizeof (rf627_old_point2D_t));
                    if ((*profile_array)[i].rf627smart_profile2D->header.flags & 0x01){
                        (*profile_array)[i].rf627smart_profile2D->intensity_count = 0;
                        (*profile_array)[i].rf627smart_profile2D->intensity =
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
                    switch ((*profile_array)[i].rf627smart_profile2D->header.data_type)
                    {
                    case DTY_ProfileNormal:
                    case DTY_ProfileInterpolated:
                        z = *(rfUint16*)(&((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + ii*4 + 2]);
                        x = *(rfInt16*)(&((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + ii*4]);
                        if (zero_points == 0 && z > 0 && x != 0)
                        {
                            pt.x = (rfFloat)((rfDouble)(x) * (rfDouble)((*profile_array)[i].rf627smart_profile2D->header.xemr) /
                                    (rfDouble)((*profile_array)[i].rf627smart_profile2D->header.discrete_value));
                            pt.z = (rfFloat)((rfDouble)(z) * (rfDouble)((*profile_array)[i].rf627smart_profile2D->header.zmr) /
                                    (rfDouble)((*profile_array)[i].rf627smart_profile2D->header.discrete_value));

                            (*profile_array)[i].rf627smart_profile2D->profile_format.points[(*profile_array)[i].rf627smart_profile2D->profile_format.points_count] = pt;
                            (*profile_array)[i].rf627smart_profile2D->profile_format.points_count++;
                            if ((*profile_array)[i].rf627smart_profile2D->header.flags & 0x01)
                            {
                                (*profile_array)[i].rf627smart_profile2D->intensity[(*profile_array)[i].rf627smart_profile2D->intensity_count] = ((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + pt_count*4 + ii];
                                (*profile_array)[i].rf627smart_profile2D->intensity_count++;
                            }
                        }else if(zero_points != 0)
                        {
                            pt.x = (rfFloat)((rfDouble)(x) * (rfDouble)((*profile_array)[i].rf627smart_profile2D->header.xemr) /
                                    (rfDouble)((*profile_array)[i].rf627smart_profile2D->header.discrete_value));
                            pt.z = (rfFloat)((rfDouble)(z) * (rfDouble)((*profile_array)[i].rf627smart_profile2D->header.zmr) /
                                    (rfDouble)((*profile_array)[i].rf627smart_profile2D->header.discrete_value));

                            (*profile_array)[i].rf627smart_profile2D->profile_format.points[(*profile_array)[i].rf627smart_profile2D->profile_format.points_count] = pt;
                            (*profile_array)[i].rf627smart_profile2D->profile_format.points_count++;
                            if ((*profile_array)[i].rf627smart_profile2D->header.flags & 0x01)
                            {
                                (*profile_array)[i].rf627smart_profile2D->intensity[(*profile_array)[i].rf627smart_profile2D->intensity_count] = ((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + pt_count*4 + ii];
                                (*profile_array)[i].rf627smart_profile2D->intensity_count++;
                            }
                        }
                        break;
                    case DTY_PixelsNormal:
                    case DTY_PixelsInterpolated:
                        z = *(rfUint16*)(&((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + ii*2]);
                        //pt.x = i;

                        (*profile_array)[i].rf627smart_profile2D->pixels_format.pixels[(*profile_array)[i].rf627smart_profile2D->pixels_format.pixels_count] = z;
                        (*profile_array)[i].rf627smart_profile2D->pixels_format.pixels_count++;
                        if ((*profile_array)[i].rf627smart_profile2D->header.flags & 0x01)
                        {
                            (*profile_array)[i].rf627smart_profile2D->intensity[(*profile_array)[i].rf627smart_profile2D->intensity_count] = ((rfUint8*)(&(((answer*)result)->data[i * dump_unit_size])))[profile_header_size + pt_count*4 + ii];
                            (*profile_array)[i].rf627smart_profile2D->intensity_count++;
                        }

                        //pt.z = (rfDouble)(z) / (rfDouble)(profile->header.discrete_value);

                        break;
                    }

                }
            }
        }

        // Cleanup test msg
        RF62X_cleanup_msg(msg);
        free(msg); msg = NULL;
        return TRUE;
    }else
    {
        TRACE(TRACE_LEVEL_WARNING, "%s", "No response to SET_AUTHORIZATION_KEY request!\n");
    }

    return FALSE;
}


rfInt8 rf627_smart_get_authorization_token_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    TRACE(TRACE_LEVEL_DEBUG, "+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = FALSE;
    rfBool existing = FALSE;

    // get authorization token
    mpack_tree_t tree;
    mpack_tree_init_data(&tree, (const char*)data, data_size);
    mpack_tree_parse(&tree);
    if (mpack_tree_error(&tree) != mpack_ok)
    {
        status = FALSE;
        mpack_tree_destroy(&tree);
        return status;
    }

    for (rfUint32 i = 0; i < vector_count(search_result); i++)
    {
        if(((scanner_base_t*)vector_get(search_result, i))->type == kRF627_SMART)
        {
            uint32_t serial = ((scanner_base_t*)vector_get(search_result, i))->rf627_smart->info_by_service_protocol.fact_general_serial;
            if (serial == device_id)
                existing = TRUE;
        }
    }

    if (existing)
    {
        RF62X_msg_t* msg = rqst_msg;
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
    return TRUE;
}
rfInt8 rf627_smart_get_authorization_token_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_get_authorization_token_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

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

    return TRUE;
}
rfBool rf627_smart_get_authorization_token_by_service_protocol(rf627_smart_t* scanner, char** token, rfUint32* token_size, rfUint32 timeout)
{
    char* cmd_name                      = "GET_AUTHORIZATION_TOKEN";
    char* data                          = NULL;
    uint32_t data_size                  = 0;
    char* data_type                     = "blob";
    uint8_t is_check_crc                = FALSE;
    uint8_t is_confirmation             = FALSE;
    uint8_t is_one_answ                 = TRUE;
    uint32_t waiting_time               = timeout;
    RF62X_answ_callback answ_clb        = rf627_smart_get_authorization_token_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_get_authorization_token_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_get_authorization_token_free_result_callback;

    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, data, data_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time,
                                             answ_clb, timeout_clb, free_clb);

    // Send test msg
    if (!RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_ERROR, "%s", "No data has been sent.\n");
    }
    else
    {
        TRACE(TRACE_LEVEL_DEBUG, "%s", "Requests were sent.\n");
    }

    void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
    if (result != NULL)
    {
        typedef struct
        {
            uint32_t status;
            char* token;
        }answer;

        *token_size = rf_strlen(((answer*)result)->token);
        *token = calloc(*token_size + 1, sizeof (char));
        memcpy(*token, ((answer*)result)->token, *token_size);

        // Cleanup test msg
        RF62X_cleanup_msg(msg);
        free(msg); msg = NULL;
        return TRUE;
    }else
    {
        TRACE(TRACE_LEVEL_WARNING, "%s", "No response to GET_AUTHORIZATION_TOKEN request!\n");
    }

    return FALSE;
}

rfInt8 rf627_smart_set_authorization_key_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    TRACE(TRACE_LEVEL_DEBUG, "+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = FALSE;
    rfBool existing = FALSE;

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

    for (rfUint32 i = 0; i < vector_count(search_result); i++)
    {
        if(((scanner_base_t*)vector_get(search_result, i))->type == kRF627_SMART)
        {
            uint32_t serial = ((scanner_base_t*)vector_get(search_result, i))->rf627_smart->info_by_service_protocol.fact_general_serial;
            if (serial == device_id)
                existing = TRUE;
        }
    }

    if (existing)
    {
        RF62X_msg_t* msg = rqst_msg;
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
    return TRUE;
}
rfInt8 rf627_smart_set_authorization_key_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_set_authorization_key_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    if (msg->result != NULL)
    {
        typedef struct
        {
            char* result;
            uint32_t status;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }

    return TRUE;
}
rfBool rf627_smart_set_authorization_key_by_service_protocol(rf627_smart_t* scanner, char* key, rfUint32 key_size, rfUint32 timeout)
{
    // Create payload
    mpack_writer_t writer;
    char* payload = NULL;
    size_t bytes = 0;				///< Number of msg bytes.
    mpack_writer_init_growable(&writer, &payload, &bytes);

    // Идентификатор сообщения для подтверждения
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


    char* cmd_name                      = "SET_AUTHORIZATION_KEY";
    char* data                          = payload;
    uint32_t data_size                  = (rfUint32)bytes;
    char* data_type                     = "mpack";
    uint8_t is_check_crc                = FALSE;
    uint8_t is_confirmation             = FALSE;
    uint8_t is_one_answ                 = TRUE;
    uint32_t waiting_time               = timeout;
    RF62X_answ_callback answ_clb        = rf627_smart_set_authorization_key_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_set_authorization_key_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_set_authorization_key_free_result_callback;

    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, data, data_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time,
                                             answ_clb, timeout_clb, free_clb);

    free(payload);

    // Send test msg
    if (!RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_ERROR, "%s", "No data has been sent.\n");
    }
    else
    {
        TRACE(TRACE_LEVEL_DEBUG, "%s", "Requests were sent.\n");
    }

    void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
    if (result != NULL)
    {
        typedef struct
        {
            char* result;
            uint32_t status;
        }answer;

        if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0 &&
                ((answer*)result)->status != 0)
        {
            // Cleanup test msg
            RF62X_cleanup_msg(msg);
            free(msg); msg = NULL;
            return TRUE;
        }else
        {
            TRACE(TRACE_LEVEL_ERROR, "%s - %s", "Authorization key not setted\n",
                  ((answer*)result)->result);
        }

        // Cleanup test msg
        RF62X_cleanup_msg(msg);
        free(msg); msg = NULL;
        return FALSE;
    }else
    {
        TRACE(TRACE_LEVEL_WARNING, "%s", "No response to SET_AUTHORIZATION_KEY request!\n");
    }

    return FALSE;
}

rfInt8 rf627_smart_read_calibration_data_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    TRACE(TRACE_LEVEL_DEBUG, "+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = FALSE;
    rfBool existing = FALSE;

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

    for (rfUint32 i = 0; i < vector_count(search_result); i++)
    {
        if(((scanner_base_t*)vector_get(search_result, i))->type == kRF627_SMART)
        {
            uint32_t serial = ((scanner_base_t*)vector_get(search_result, i))->rf627_smart->info_by_service_protocol.fact_general_serial;
            if (serial == device_id)
                existing = TRUE;
        }
    }

    if (existing)
    {
        RF62X_msg_t* msg = rqst_msg;
        typedef struct
        {
            char* result;

            rfUint32 m_Serial;
            rfUint32 m_DataRowLength;
            rfUint32 m_Width;
            rfUint32 m_Height;
            rfUint32 m_MultW;
            rfUint32 m_MultH;
            rfInt m_TimeStamp;
        }answer;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        mpack_node_t root = mpack_tree_root(&tree);

        if (mpack_node_map_contains_cstr(root, "result"))
        {
            mpack_node_t result_data = mpack_node_map_cstr(root, "result");
            uint32_t result_size = (rfUint32)mpack_node_strlen(result_data) + 1;
            answer* answ =  (answer*)msg->result;
            answ->result = mpack_node_cstr_alloc(result_data, result_size);

            if (rf_strcmp(answ->result, "RF_OK") == 0)
            {
                if (mpack_node_map_contains_cstr(root, "serial"))
                {
                    mpack_node_t serial = mpack_node_map_cstr(root, "serial");
                    answ->m_Serial = mpack_node_u32(serial);
                }
                if (mpack_node_map_contains_cstr(root, "data_row_length"))
                {
                    mpack_node_t data_row_length = mpack_node_map_cstr(root, "data_row_length");
                    answ->m_DataRowLength = mpack_node_u32(data_row_length);
                }
                if (mpack_node_map_contains_cstr(root, "width"))
                {
                    mpack_node_t width = mpack_node_map_cstr(root, "width");
                    answ->m_Width = mpack_node_u32(width);
                }
                if (mpack_node_map_contains_cstr(root, "height"))
                {
                    mpack_node_t height = mpack_node_map_cstr(root, "height");
                    answ->m_Height = mpack_node_u32(height);
                }
                if (mpack_node_map_contains_cstr(root, "mult_w"))
                {
                    mpack_node_t mult_w = mpack_node_map_cstr(root, "mult_w");
                    answ->m_MultW = mpack_node_u32(mult_w);
                }
                if (mpack_node_map_contains_cstr(root, "mult_h"))
                {
                    mpack_node_t mult_h = mpack_node_map_cstr(root, "mult_h");
                    answ->m_MultH = mpack_node_u32(mult_h);
                }
                if (mpack_node_map_contains_cstr(root, "time_stamp"))
                {
                    mpack_node_t time_stamp = mpack_node_map_cstr(root, "time_stamp");
                    answ->m_TimeStamp = mpack_node_i32(time_stamp);
                }
            }
        }

        status = TRUE;
    }


    mpack_tree_destroy(&tree);
    return TRUE;
}
rfInt8 rf627_smart_read_calibration_data_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_read_calibration_data_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    if (msg->result != NULL)
    {
        typedef struct
        {
            char* result;

            rfUint32 m_Serial;
            rfUint32 m_DataRowLength;
            rfUint32 m_Width;
            rfUint32 m_Height;
            rfUint32 m_MultW;
            rfUint32 m_MultH;
            rfInt m_TimeStamp;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }

    return TRUE;
}
rfBool rf627_smart_read_calibration_table_by_service_protocol(rf627_smart_t* scanner, rfUint32 timeout)
{

    if (scanner->calib_table.m_Data != NULL)
    {
        free(scanner->calib_table.m_Data);
        scanner->calib_table.m_Data = NULL;
        scanner->calib_table.m_DataSize = 0;
    }

    scanner->calib_table.m_Data = NULL;
    scanner->calib_table.m_DataSize = 0;

    scanner->calib_table.m_Serial = scanner->info_by_service_protocol.fact_general_serial;
    scanner->calib_table.m_CRC16 = 0;
    scanner->calib_table.m_Type = 0x03;

    parameter_t* width = rf627_smart_get_parameter(scanner, "fact_sensor_width");
    parameter_t* height = rf627_smart_get_parameter(scanner, "fact_sensor_height");

    scanner->calib_table.m_Width = width->val_uint32->value;
    scanner->calib_table.m_Height = height->val_uint32->value;

    scanner->calib_table.m_DataRowLength = 8192;

    scanner->calib_table.m_MultW = 1;
    scanner->calib_table.m_MultH = 2;

    scanner->calib_table.m_TimeStamp = time(NULL);

    return TRUE;

    char* cmd_name                      = "GET_CALIBRATION_INFO";
    char* data                          = NULL;
    uint32_t data_size                  = 0;
    char* data_type                     = "blob";
    uint8_t is_check_crc                = FALSE;
    uint8_t is_confirmation             = FALSE;
    uint8_t is_one_answ                 = TRUE;
    uint32_t waiting_time               = timeout;
    RF62X_answ_callback answ_clb        = rf627_smart_read_calibration_data_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_read_calibration_data_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_read_calibration_data_free_result_callback;

    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, data, data_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time,
                                             answ_clb, timeout_clb, free_clb);

    // Send test msg
    if (!RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_ERROR, "%s", "No data has been sent.\n");
    }
    else
    {
        TRACE(TRACE_LEVEL_DEBUG, "%s", "Requests were sent.\n");
    }

    void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
    if (result != NULL)
    {
        typedef struct
        {
            char* result;

            rfUint32 m_Serial;
            rfUint32 m_DataRowLength;
            rfUint32 m_Width;
            rfUint32 m_Height;
            rfUint32 m_MultW;
            rfUint32 m_MultH;
            rfInt m_TimeStamp;
        }answer;

        answer* answ = (answer*)result;

        if (rf_strcmp(answ->result, "RF_OK") == 0)
        {
            if (scanner->calib_table.m_Data != NULL)
            {
                free(scanner->calib_table.m_Data);
                scanner->calib_table.m_Data = NULL;
                scanner->calib_table.m_DataSize = 0;
            }

            scanner->calib_table.m_Data = NULL;
            scanner->calib_table.m_DataSize = 0;

            scanner->calib_table.m_Serial = answ->m_Serial;
            scanner->calib_table.m_CRC16 = 0;
            scanner->calib_table.m_Type = 0x03;
            scanner->calib_table.m_DataRowLength = answ->m_DataRowLength;
            scanner->calib_table.m_Width = answ->m_Width;
            scanner->calib_table.m_Height = answ->m_Height;

            scanner->calib_table.m_MultW = answ->m_MultW;
            scanner->calib_table.m_MultH = answ->m_MultH;

            scanner->calib_table.m_TimeStamp = answ->m_TimeStamp;
            // Cleanup test msg
            RF62X_cleanup_msg(msg);
            free(msg); msg = NULL;
            return TRUE;
        }else
        {
            if (scanner->calib_table.m_Data != NULL)
            {
                free(scanner->calib_table.m_Data);
                scanner->calib_table.m_Data = NULL;
                scanner->calib_table.m_DataSize = 0;
            }

            scanner->calib_table.m_Data = NULL;
            scanner->calib_table.m_DataSize = 0;

            scanner->calib_table.m_Serial = scanner->info_by_service_protocol.fact_general_serial;
            scanner->calib_table.m_CRC16 = 0;
            scanner->calib_table.m_Type = 0x03;

            parameter_t* width = rf627_smart_get_parameter(scanner, "fact_sensor_width");
            parameter_t* height = rf627_smart_get_parameter(scanner, "fact_sensor_height");

            scanner->calib_table.m_Width = width->val_uint32->value;
            scanner->calib_table.m_Height = height->val_uint32->value;

            scanner->calib_table.m_DataRowLength = 8192;

            scanner->calib_table.m_MultW = 1;
            scanner->calib_table.m_MultH = 2;

            scanner->calib_table.m_TimeStamp = time(NULL);
        }

        // Cleanup test msg
        RF62X_cleanup_msg(msg);
        free(msg); msg = NULL;
        return FALSE;
    }else
    {
        if (scanner->calib_table.m_Data != NULL)
        {
            free(scanner->calib_table.m_Data);
            scanner->calib_table.m_Data = NULL;
            scanner->calib_table.m_DataSize = 0;
        }

        scanner->calib_table.m_Data = NULL;
        scanner->calib_table.m_DataSize = 0;

        scanner->calib_table.m_Serial = scanner->info_by_service_protocol.fact_general_serial;
        scanner->calib_table.m_CRC16 = 0;
        scanner->calib_table.m_Type = 0x03;

        parameter_t* width = rf627_smart_get_parameter(scanner, "fact_sensor_width");
        parameter_t* height = rf627_smart_get_parameter(scanner, "fact_sensor_height");

        scanner->calib_table.m_Width = width->val_uint32->value;
        scanner->calib_table.m_Height = height->val_uint32->value;

        scanner->calib_table.m_DataRowLength = 8192;

        scanner->calib_table.m_MultW = 1;
        scanner->calib_table.m_MultH = 2;

        scanner->calib_table.m_TimeStamp = time(NULL);
    }

    return FALSE;
}

uint16_t gen_crc16(const uint8_t *data, uint32_t len)
{
    uint16_t crc = 0;
    uint16_t* data16 = (uint16_t*)data;

    while(len > 1)
    {
        crc += 44111 * *data16++;
        len -= sizeof(uint16_t);
    }
    if (len > 0) crc += *(uint8_t*)data16;
    crc = crc ^ (crc >> 8);
    return crc;
}
rfInt8 rf627_smart_write_calibration_data_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    TRACE(TRACE_LEVEL_DEBUG, "+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = FALSE;
    rfBool existing = FALSE;

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

    for (rfUint32 i = 0; i < vector_count(search_result); i++)
    {
        if(((scanner_base_t*)vector_get(search_result, i))->type == kRF627_SMART)
        {
            uint32_t serial = ((scanner_base_t*)vector_get(search_result, i))->rf627_smart->info_by_service_protocol.fact_general_serial;
            if (serial == device_id)
                existing = TRUE;
        }
    }

    if (existing)
    {
        RF62X_msg_t* msg = rqst_msg;
        typedef struct
        {
            char* result;
        }answer;

        mpack_node_t root = mpack_tree_root(&tree);
        mpack_node_t result_data = mpack_node_map_cstr(root, "result");
        uint32_t result_size = (rfUint32)mpack_node_strlen(result_data) + 1;

        if (msg->result == NULL)
        {
            msg->result = calloc(1, sizeof (answer));
        }

        ((answer*)msg->result)->result = mpack_node_cstr_alloc(result_data, result_size);

        status = TRUE;
    }


    mpack_tree_destroy(&tree);
    return TRUE;
}
rfInt8 rf627_smart_write_calibration_data_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_write_calibration_data_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    if (msg->result != NULL)
    {
        typedef struct
        {
            char* result;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }

    return TRUE;
}
rfBool rf627_smart_write_calibration_data_by_service_protocol(rf627_smart_t* scanner, rfUint32 timeout)
{
    // Create payload
    mpack_writer_t writer;
    char* payload = NULL;
    size_t bytes = 0;				///< Number of msg bytes.
    mpack_writer_init_growable(&writer, &payload, &bytes);

    // Идентификатор сообщения для подтверждения
    mpack_start_map(&writer, 10);
    {
        mpack_write_cstr(&writer, "type");
        mpack_write_uint(&writer, scanner->calib_table.m_Type);

        mpack_write_cstr(&writer, "crc");
        mpack_write_uint(&writer, scanner->calib_table.m_CRC16);

        mpack_write_cstr(&writer, "serial");
        mpack_write_uint(&writer, scanner->calib_table.m_Serial);

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

        mpack_write_cstr(&writer, "data");
        mpack_write_bin(&writer, (const char*)scanner->calib_table.m_Data, scanner->calib_table.m_DataSize);
    }mpack_finish_map(&writer);

    // finish writing
    if (mpack_writer_destroy(&writer) != mpack_ok) {
        fprintf(stderr, "An error occurred encoding the data!\n");
        return FALSE;
    }


    char* cmd_name                      = "SET_CALIBRATION_DATA";
    char* data                          = payload;
    uint32_t data_size                  = (rfUint32)bytes;
    char* data_type                     = "blob";
    uint8_t is_check_crc                = TRUE;
    uint8_t is_confirmation             = TRUE;
    uint8_t is_one_answ                 = TRUE;
    uint32_t waiting_time               = timeout;
    RF62X_answ_callback answ_clb        = rf627_smart_write_calibration_data_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_write_calibration_data_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_write_calibration_data_free_result_callback;

    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, data, data_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time,
                                             answ_clb, timeout_clb, free_clb);

    free(payload);

    // Send test msg
    if (!RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_ERROR, "%s", "No data has been sent.\n");
    }
    else
    {
        TRACE(TRACE_LEVEL_DEBUG, "%s", "Requests were sent.\n");
    }

    void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
    if (result != NULL)
    {
        typedef struct
        {
            char* result;
        }answer;

        if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0)
        {
            // Cleanup test msg
            RF62X_cleanup_msg(msg);
            free(msg); msg = NULL;
            return TRUE;
        }

        // Cleanup test msg
        RF62X_cleanup_msg(msg);
        free(msg); msg = NULL;
        return FALSE;
    }

    return FALSE;
}


rfInt8 rf627_smart_save_calibration_data_callback(char* data, uint32_t data_size, uint32_t device_id, void* rqst_msg)
{
    answ_count++;
    TRACE(TRACE_LEVEL_DEBUG, "+ Get answer to %s command, rqst-id: %" PRIu64 ", payload size: %d\n",
           ((RF62X_msg_t*)rqst_msg)->cmd_name, ((RF62X_msg_t*)rqst_msg)->_uid, data_size);

    int32_t status = FALSE;
    rfBool existing = FALSE;

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

    for (rfUint32 i = 0; i < vector_count(search_result); i++)
    {
        if(((scanner_base_t*)vector_get(search_result, i))->type == kRF627_SMART)
        {
            uint32_t serial = ((scanner_base_t*)vector_get(search_result, i))->rf627_smart->info_by_service_protocol.fact_general_serial;
            if (serial == device_id)
                existing = TRUE;
        }
    }

    if (existing)
    {
        RF62X_msg_t* msg = rqst_msg;
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

        ((answer*)msg->result)->result = mpack_node_cstr_alloc(result_data, result_size);

        status = TRUE;
    }


    mpack_tree_destroy(&tree);
    return TRUE;
}
rfInt8 rf627_smart_save_calibration_data_timeout_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Get timeout to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    return TRUE;
}
rfInt8 rf627_smart_save_calibration_data_free_result_callback(void* rqst_msg)
{
    RF62X_msg_t* msg = rqst_msg;

    TRACE(TRACE_LEVEL_DEBUG, "- Free result to %s command, rqst-id: %" PRIu64 ".\n",
           msg->cmd_name, msg->_uid);

    if (msg->result != NULL)
    {
        typedef struct
        {
            char* result;
        }answer;

        free(((answer*)msg->result)->result);
        free(msg->result);
        msg->result = NULL;
    }

    return TRUE;
}
rfBool rf627_smart_save_calibration_data_by_service_protocol(rf627_smart_t* scanner, rfUint32 timeout)
{
    char* cmd_name                      = "SAVE_CALIBRATION_DATA";
    char* data                          = NULL;
    uint32_t data_size                  = 0;
    char* data_type                     = "blob";
    uint8_t is_check_crc                = FALSE;
    uint8_t is_confirmation             = FALSE;
    uint8_t is_one_answ                 = TRUE;
    uint32_t waiting_time               = timeout;
    RF62X_answ_callback answ_clb        = rf627_smart_save_calibration_data_callback;
    RF62X_timeout_callback timeout_clb  = rf627_smart_save_calibration_data_timeout_callback;
    RF62X_free_callback free_clb        = rf627_smart_save_calibration_data_free_result_callback;

    RF62X_msg_t* msg = RF62X_create_rqst_msg(cmd_name, data, data_size, data_type,
                                             is_check_crc, is_confirmation, is_one_answ,
                                             waiting_time,
                                             answ_clb, timeout_clb, free_clb);

    // Send test msg
    if (!RF62X_channel_send_msg(&scanner->channel, msg))
    {
        TRACE(TRACE_LEVEL_ERROR, "%s", "No data has been sent.\n");
    }
    else
    {
        TRACE(TRACE_LEVEL_DEBUG, "%s", "Requests were sent.\n");
    }

    void* result = RF62X_find_result_to_rqst_msg(&scanner->channel, msg, waiting_time);
    if (result != NULL)
    {
        typedef struct
        {
            char* result;
        }answer;

        if (rf_strcmp(((answer*)result)->result, "RF_OK") == 0)
        {
            // Cleanup test msg
            RF62X_cleanup_msg(msg);
            free(msg); msg = NULL;
            return TRUE;
        }

        // Cleanup test msg
        RF62X_cleanup_msg(msg);
        free(msg); msg = NULL;
        return FALSE;
    }

    return FALSE;
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
