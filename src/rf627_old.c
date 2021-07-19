#include "rf62X_sdk.h"
#include "iostream_platform.h"
#include "custom_string.h"
#include "memory_platform.h"
#include "netwok_platform.h"
#include <stdarg.h>
#include <time.h>

//#include <pthread.h>

#define RF627_OLD_API_VERSION       0x14010a00  //20.01.10.0

#define RF627_REENUM_IFS_ON_SEARCH  1

#define RF627_DEVICE_ID             627

#define RF627_SERVICE_PORT          50011
#define RF627_STREAM_PORT           50001

#define RF627_RECV_TIMEOUT          100

#define RF627_PROFILE_SIZE          648
#define RF627_EXT_PROFILE_SIZE      1296

#define RF627_IMAGE_WIDTH           648
#define RF627_IMAGE_HEIGHT          488
#define RF627_IMAGE_SIZE            (RF627_IMAGE_WIDTH * RF627_IMAGE_HEIGHT)

#define RF627_MAX_PAYLOAD_SIZE      32754

#define RF627_API_MAX_ERROR_TEXT_LENGTH     256

#define RF627_MAX_LOG_ENTRIES_PER_PAYLOAD   (RF627_MAX_PAYLOAD_SIZE / sizeof(rf627_log_record_t))

#define RF627_SERVICE_PROTO_REPEAT_RATE     5

#define WRITE_PARAMS_TIMEOUT        (3 * 1000)
#define FLUSH_PARAMS_TIMEOUT        (3 * 1000)
#define REBOOT_TIMEOUT              (2 * 1000)
#define READ_PARAMS_TIMEOUT         (3 * 1000)
#define WRITE_CHUNK_TIMEOUT         (10 * 1000)
#define FLUSH_FIRMWARE_TIMEOUT      (2 * 1000)
#define WRITE_SPI_TIMEOUT           (100 * 1000)
#define WRITE_SPI_FINISHED_BS       0

//Режим отражения изображения (в фэктори) или профиля (в юзер)
typedef enum{
    FM_NO					= 0x00,
    FM_X					= 0x01,
    FM_Z					= 0x02,
    FM_XZ					= 0x03
}flipMode_t;

//Формат представления профиля
typedef enum{
    DF_PIXELS				= 0x00,
    DF_PROFILE				= 0x01,
    DF_PIXELS_INTRP			= 0x02,
    DF_PROFILE_INTRP		= 0x03
}dataFormat_t;

//Режим первичной обработки видео
typedef enum{
    PM_ACCURACY				= 0x00,
    PM_WELDING				= 0x01
}procMode_t;

//Режим выбора пика для рассчета профиля
typedef enum{
    PM_MAX_INTENSITY		= 0x00,
    PM_FIRST				= 0x01,
    PM_LAST					= 0x02,
    PM_NUMBER_2				= 0x03,
    PM_NUMBER_3				= 0x04,
    PM_NUMBER_4				= 0x05,
    PM_NUMBER_5				= 0x06,
    PM_NUMBER_6				= 0x07,
}peakMode_t;

//Режимы управления положением ROI
typedef enum{
    RPM_MANUAL				= 0,
    RPM_AUTO				= 1
}roiPosMode_t;

//Состояния соединения по сети
typedef enum{
    LS_DISCONNECTED			= 0,
    LS_CONNECTED			= 1
}linkState_t;

//Скорости соединения по сети
typedef enum{
    LS_UNKN					= 0,
    LS_10MBIT				= 10,
    LS_100MBIT				= 100,
    LS_1GBIT				= 1000,
}linkSpeed_t;

//Режимы работы лазера
typedef enum{
    LASER_PLAIN_INT				= 0x00,
    LASER_PLAIN_INT_INV			= 0x02,
    LASER_PLAIN_EXT				= 0x01,
    LASER_PLAIN_EXT_INV			= 0x03,
    LASER_STROBE				= 0x04,
    LASER_STROBE_INV			= 0x05,
    LASER_ALWAYS_ONE			= 0x06,
    LASER_ALWAYS_ZERO			= 0x07,
    LASER_HEART_BEAT			= 0x10,
    LASER_HEART_BEAT_INV		= 0x12,
    LASER_PULS_SLOW				= 0x20,
    LASER_PULS_SLOW_INV			= 0x22,
    LASER_PULS_FAST				= 0x30,
    LASER_PULS_FAST_INV			= 0x32,
}laserMode_t;

//Параметры запуска экспозиции для входа №1
typedef enum{
    IN1_EVENT_IGEN				= 0,
    IN1_EVENT_EXT				= 1,
    IN1_EVENT_SREQ				= 3
}in1Event_t;

//Режим срабатывания входа №1
typedef enum{
    IN1_MODE_RISE				= 0,
    IN1_MODE_FALL				= 1,
    IN1_MODE_LVL1				= 2,
    IN1_MODE_LVL0				= 3
}in1Mode_t;

//Режим срабатывания входа №2
typedef enum{
    IN2_MODE_LVL				= 0,
    IN2_MODE_PHASE				= 1
}in2Mode_t;

//Режим работы входа №2
typedef enum{
    IN3_MODE_RISE				= 0,
    IN3_MODE_FALL				= 1
}in3Mode_t;

//Режим работы выходов
typedef enum{
    OUT_MODE_EXP_START			= 0,
    OUT_MODE_IN1_LOG_LVL		= 1,
    OUT_MODE_IN1_RISE			= 2,
    OUT_MODE_IN1_FALL			= 3,
    OUT_MODE_IN2_LOG_LVL		= 4,
    OUT_MODE_IN2_RISE			= 5,
    OUT_MODE_IN2_FALL			= 6,
    OUT_MODE_IN3_LOG_LVL		= 7,
    OUT_MODE_IN3_RISE			= 8,
    OUT_MODE_IN3_FALL			= 9,
    OUT_MODE_EXP_TIME			= 10
}outMode_t;

//Селектор координаты Y для профилей
typedef enum{
    YA_SYSTEM_TIME				= 0,
    YA_STEP_COUNTER				= 1,
    YA_MEASURES_COUNTER			= 2,
}yAxisSource_t;

//pthread_mutex_t _mutex;

rfUint32 rf627_old_api_version()
{
    return RF627_OLD_API_VERSION;
}


int rf627_old_mutex_lock()
{
//    return pthread_mutex_lock(&_mutex);
    return 0;
}

int rf627_old_mutex_trylock()
{
//    rfInt error = pthread_mutex_trylock(&_mutex);
//    if (error == 0) {
//        /*... have the lock */
//        return error;
//    } else if (error == EBUSY) {
//        /*... failed to get the lock because another thread holds lock */
//        return error;
//    } else if (error == EOWNERDEAD) {
//        /*... got the lock, but the critical section state may not be consistent */
//        return error;
//    } else {
//        switch (error) {
//        case EAGAIN:
//            /*... recursively locked too many times */
//            return error;
//            break;
//        case EINVAL:
//            /*... thread priority higher than mutex priority ceiling */
//            return error;
//            break;
//        case ENOTRECOVERABLE:
//            /*... mutex suffered EOWNERDEAD, and is no longer consistent */
//            return error;
//            break;
//        default:
//            /*...some other as yet undocumented failure reason */
//            return error;
//            break;
//        }
//    }
//    return error;
    return 0;
}

int rf627_old_mutex_unlock()
{
//    return pthread_mutex_unlock(&_mutex);
    return 0;
}


#ifdef _WIN32
extern void usleep(__int64 usec);
#endif

uint8_t rf627_old_search_by_service_protocol(vector_t *result, rfUint32 ip_addr, rfUint32 timeout)
{
    void* s;
    rfUint32 dst_ip_addr, srs_ip_addr;
    rfUint16 dst_port, srs_port;
    rfInt nret;
    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);

    // pthread_mutex_lock(&_mutex);

    // create hello msg request
    rf627_old_header_msg_t hello_msg =
            rf627_protocol_old_create_hello_msg_request();

    // pack hello msg request to packet
    rfUint32 request_packet_size =
            rf627_protocol_old_pack_hello_msg_request_to_packet(
                (rfUint8*)TX, TX_SIZE, &hello_msg);

    s = network_platform.
            network_methods.create_udp_socket();

    if (s == (void*)RF_SOCKET_ERROR) {
        return 1;
    }

    network_platform.network_methods.set_socket_recv_timeout(
                s, RF627_RECV_TIMEOUT);

    nret = 1;
    network_platform.network_methods.set_broadcast_socket_option(s);

    //send_addr.sin_family = RF_AF_INET;
    //send_addr.sin_addr = network_platform.network_methods.hton_long(RF_INADDR_BROADCAST);
    dst_ip_addr = 0xffffffff;
    dst_port = RF627_SERVICE_PORT;

    //from_addr.sin_family = RF_AF_INET;
    srs_ip_addr  = ip_addr;
    srs_port = 0;

    nret = network_platform.network_methods.socket_bind(s, srs_ip_addr, srs_port);
            //network_methods.socket_bind(s, &from_addr, sizeof(from_addr));


    if (nret != (rfInt)RF_SOCKET_ERROR)
    {
        if (rf627_protocol_send_packet_by_udp(
                    s, TX, request_packet_size, dst_ip_addr, dst_port, 0, NULL))
        {
            usleep(timeout*1000);
            rfUint32 response_packet_size =
                    rf627_protocol_old_get_size_of_response_hello_packet();
            do
            {
                nret = network_platform.network_methods.recv_data_from(
                            s, RX, RX_SIZE, &srs_ip_addr, &srs_port);

                if (nret == RF_SOCKET_ERROR)
                {
                    //std::cout << "errno " << ::WSAGetLastError() << std::endl;
                }

                if (nret == (rfInt)response_packet_size)
                {
                    rfSize confirm_packet_size =
                            rf627_protocol_old_create_confirm_packet_from_response_packet(
                                TX, TX_SIZE, RX, RX_SIZE);
                    if(confirm_packet_size > 0)
                    {
                        srs_port = dst_port;
                        rf627_protocol_send_packet_by_udp(
                                    s, TX, confirm_packet_size, srs_ip_addr, srs_port, 0, NULL);
                    }

                    rf627_old_header_msg_t response_header_msg =
                            rf627_protocol_old_unpack_header_msg_from_hello_packet(RX);

                    rf627_old_device_info_t response_payload_msg =
                            rf627_protocol_old_unpack_payload_msg_from_hello_packet(RX);


                    rfBool existing = 0;

                    for (rfUint32 i = 0; i < vector_count(result); i++)
                    {
                        if(((scanner_base_t*)vector_get(result, i))->type == kRF627_OLD)
                        {
                            if (!memory_platform.
                                    rf_memcmp(((scanner_base_t*)vector_get(result, i))->
                                              rf627_old->factory_params.network.mac,
                                              response_payload_msg.hardware_address, 6))
                            {
                                existing = 1;
                                break;
                            }

                        }
                    }

                    if (!existing)
                    {
                        scanner_base_t* rf627 =
                                memory_platform.rf_calloc(1, sizeof(scanner_base_t));

                        rf627->type = kRF627_OLD;
                        rf627->rf627_old = rf627_old_create_from_hello_msg(
                                    &response_payload_msg, response_header_msg.msg_count + 1);
                        vector_add(result, rf627);
                    }
                }
            }
            while (nret > 0);
        }
        network_platform.network_methods.close_socket(s);
    }

//    _mx[0].unlock();

    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);

    return 0;
}

rf627_old_t* rf627_old_create_from_hello_msg(
        void* msg_info, rfUint16 init_msg_count)
{
    rf627_old_t* rf627_old = memory_platform.rf_calloc(1, sizeof (rf627_old_t));

    vector_init(&rf627_old->params_list);

    // copy device name
    memory_platform.rf_memcpy(
                rf627_old->user_params.general.name,
                ((rf627_old_device_info_t*)msg_info)->name,
                rf_strlen(((rf627_old_device_info_t*)msg_info)->name) + 1);

    // copy device_id
    rf627_old->factory_params.general.device_id =
            ((rf627_old_device_info_t*)msg_info)->device_id;

    // copy serial_number
    rf627_old->factory_params.general.serial =
            ((rf627_old_device_info_t*)msg_info)->serial_number;

    // copy firmware_version
    rf627_old->factory_params.general.firmware_ver =
            ((rf627_old_device_info_t*)msg_info)->firmware_version;

    // copy hardware_version
    rf627_old->factory_params.general.hardware_ver =
            ((rf627_old_device_info_t*)msg_info)->hardware_version;

    // copy config_version
    rf627_old->options.version =
            ((rf627_old_device_info_t*)msg_info)->config_version;

    // copy fsbl_version
    rf627_old->factory_params.general.fsbl_version =
            ((rf627_old_device_info_t*)msg_info)->fsbl_version;

    // copy z_begin
    rf627_old->factory_params.general.base_z =
            ((rf627_old_device_info_t*)msg_info)->z_begin;

    // copy z_range
    rf627_old->factory_params.general.range_z =
            ((rf627_old_device_info_t*)msg_info)->z_range;

    // copy x_smr
    rf627_old->factory_params.general.range_x_start =
            ((rf627_old_device_info_t*)msg_info)->x_smr;

    // copy x_emr
    rf627_old->factory_params.general.range_x_end =
            ((rf627_old_device_info_t*)msg_info)->x_emr;

    // copy eth_speed
    rf627_old->user_params.network.speed =
            ((rf627_old_device_info_t*)msg_info)->eth_speed;

    // copy ip_address
    memory_platform.rf_memcpy(
                rf627_old->user_params.network.ip_address,
                ((rf627_old_device_info_t*)msg_info)->ip_address, 4);

    // copy net_mask
    memory_platform.rf_memcpy(
                rf627_old->user_params.network.net_mask,
                ((rf627_old_device_info_t*)msg_info)->net_mask, 4);

    // copy gateway_ip
    memory_platform.rf_memcpy(
                rf627_old->user_params.network.gateway_ip,
                ((rf627_old_device_info_t*)msg_info)->gateway_ip, 4);

    // copy host_ip
    memory_platform.rf_memcpy(
                rf627_old->user_params.network.host_ip,
                ((rf627_old_device_info_t*)msg_info)->host_ip, 4);

    // copy stream_port
    rf627_old->user_params.network.stream_port =
            ((rf627_old_device_info_t*)msg_info)->stream_port;

    // copy http_port
    rf627_old->user_params.network.http_port =
            ((rf627_old_device_info_t*)msg_info)->http_port;

    // copy service_port
    rf627_old->user_params.network.service_port =
            ((rf627_old_device_info_t*)msg_info)->service_port;

    // copy hardware_address
    memory_platform.rf_memcpy(
                rf627_old->factory_params.network.mac,
                ((rf627_old_device_info_t*)msg_info)->hardware_address, 6);

//    // copy max_payload_size
//    rf627_old->user_params.network.max_payload_size =
//            ((rf627_old_device_info_t*)msg_info)->max_payload_size;

    // copy stream_enabled
    rf627_old->user_params.stream.enable =
            ((rf627_old_device_info_t*)msg_info)->stream_enabled;

    // copy stream_format
    rf627_old->user_params.stream.format =
            ((rf627_old_device_info_t*)msg_info)->stream_format;



    rf627_old->info_by_service_protocol.device_name = memory_platform.rf_calloc(
                1, rf_strlen(rf627_old->user_params.general.name) + 1);

    memory_platform.rf_memcpy(rf627_old->info_by_service_protocol.device_name,
                              rf627_old->user_params.general.name,
                              rf_strlen(rf627_old->user_params.general.name) + 1);

    rf627_old->info_by_service_protocol.serial_number = rf627_old->factory_params.general.serial;

    memory_platform.rf_memcpy(
                rf627_old->info_by_service_protocol.ip_address,
                rf627_old->user_params.network.ip_address, 4);

    memory_platform.rf_memcpy(
                rf627_old->info_by_service_protocol.mac_address,
                rf627_old->factory_params.network.mac, 6);

    rf627_old->info_by_service_protocol.profile_port = rf627_old->user_params.network.stream_port;
    rf627_old->info_by_service_protocol.service_port = rf627_old->user_params.network.service_port;
    rf627_old->info_by_service_protocol.firmware_version = rf627_old->factory_params.general.firmware_ver;
    rf627_old->info_by_service_protocol.hardware_version = rf627_old->factory_params.general.hardware_ver;
    rf627_old->info_by_service_protocol.z_begin = rf627_old->factory_params.general.base_z;
    rf627_old->info_by_service_protocol.z_range = rf627_old->factory_params.general.range_z;
    rf627_old->info_by_service_protocol.x_begin = rf627_old->factory_params.general.range_x_start;
    rf627_old->info_by_service_protocol.x_end = rf627_old->factory_params.general.range_x_end;

    rf627_old->msg_count = init_msg_count;
    rf627_old->host_ip = network_platform.network_settings.host_ip_addr;
    return rf627_old;
}

rf627_old_hello_info_by_service_protocol* rf627_old_get_info_about_scanner_by_service_protocol(rf627_old_t* scanner)
{
    return &scanner->info_by_service_protocol;
}


rfBool rf627_old_connect(rf627_old_t* scanner)
{
    rfUint32 recv_ip_addr;
    rfUint16 recv_port;
    rfInt nret;

    if (scanner->options.version > rf627_old_api_version())
    {
        iostream_platform.trace_error("This SDK version is not suitable");
        return FALSE;
    }

    scanner->m_svc_sock =
            network_platform.network_methods.create_udp_socket();

    if (scanner->m_svc_sock == (void*)RF_SOCKET_ERROR)
    {
        return FALSE;
    }

    network_platform.network_methods.set_socket_recv_timeout(
                scanner->m_svc_sock, RF627_RECV_TIMEOUT);


    //recv_addr.sin_family = RF_AF_INET;
    recv_ip_addr = scanner->host_ip;
    recv_port = 0;
    //recv_addr.sin_addr = RF_INADDR_ANY;

    nret = network_platform.network_methods.socket_bind(
                scanner->m_svc_sock, recv_ip_addr, recv_port);
    if (nret == RF_SOCKET_ERROR)
    {
        network_platform.network_methods.close_socket(scanner->m_svc_sock);
        scanner->m_svc_sock = NULL;
        return FALSE;
    }


    scanner->m_data_sock =
            network_platform.network_methods.create_udp_socket();
    if (scanner->m_data_sock != (void*)RF_SOCKET_ERROR)
    {
        nret = 1;
        network_platform.network_methods.set_reuseaddr_socket_option(scanner->m_data_sock);

        network_platform.network_methods.set_socket_recv_timeout(
                    scanner->m_data_sock, RF627_RECV_TIMEOUT);
        //recv_addr.sin_family = RF_AF_INET;
        recv_port = scanner->user_params.network.stream_port;

        //recv_addr.sin_addr = RF_INADDR_ANY;
        recv_ip_addr = scanner->host_ip;

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

void rf627_old_disconnect(rf627_old_t* scanner)
{
    if (scanner->m_svc_sock != NULL &&
            scanner->m_svc_sock != (void*)RF_SOCKET_ERROR)
    {
        network_platform.network_methods.close_socket(scanner->m_svc_sock);
        scanner->m_svc_sock = NULL;
    }
    if (scanner->m_data_sock != NULL &&
            scanner->m_data_sock != (void*)RF_SOCKET_ERROR)
    {
        network_platform.network_methods.close_socket(scanner->m_data_sock);
        scanner->m_data_sock = NULL;
    }
}

rfBool rf627_old_check_connection_by_service_protocol(
        rf627_old_t* scanner, rfUint32 timeout)
{

    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);


    rfUint32 dst_ip_addr;
    rfUint16 dst_port;
    rfBool ret = FALSE;

    // create hello msg request
    rf627_old_header_msg_t hello_msg =
            rf627_protocol_old_create_hello_msg_request();

    // pack hello msg request to packet
    rfUint32 request_packet_size =
            rf627_protocol_old_pack_hello_msg_request_to_packet(
                (rfUint8*)TX, TX_SIZE, &hello_msg);

    dst_ip_addr = scanner->user_params.network.ip_address[0] << 24 |
                                                                scanner->user_params.network.ip_address[1] << 16 |
                                                                                                              scanner->user_params.network.ip_address[2] << 8 |
                                                                                                                                                            scanner->user_params.network.ip_address[3];
    dst_port = scanner->user_params.network.service_port;

    if (rf627_protocol_send_packet_by_udp(
                scanner->m_svc_sock, TX, request_packet_size, dst_ip_addr, dst_port, 0, NULL))
    {
        usleep(timeout*1000);
        rfUint32 response_packet_size =
                rf627_protocol_old_get_size_of_response_hello_packet();

        rfInt nret = network_platform.network_methods.recv_data(
                    scanner->m_svc_sock, RX, response_packet_size);

        if (nret == (rfInt)response_packet_size)
        {
            rfSize confirm_packet_size =
                    rf627_protocol_old_create_confirm_packet_from_response_packet(
                        TX, TX_SIZE, RX, RX_SIZE);
            if(confirm_packet_size > 0)
            {
                rf627_protocol_send_packet_by_udp(
                            scanner->m_svc_sock, TX, confirm_packet_size, dst_ip_addr, dst_port, 0, 0);
            }

            rf627_old_header_msg_t response_header_msg =
                    rf627_protocol_old_unpack_header_msg_from_hello_packet(RX);

            if(response_header_msg.serial_number == scanner->factory_params.general.serial)
            {
                ret = TRUE;
            }
        }
    }

    //    _mx[0].unlock();

    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);

    return ret;

}

void rf627_old_free(rf627_old_t* scanner)
{
    network_platform.network_methods.close_socket(scanner->m_data_sock);
    network_platform.network_methods.close_socket(scanner->m_svc_sock);

    while (vector_count(scanner->params_list) > 0)
    {
        parameter_t* p = vector_get(scanner->params_list, vector_count(scanner->params_list)-1);
        free_parameter(p, kRF627_OLD);

        vector_delete(scanner->params_list, vector_count(scanner->params_list)-1);
    }

    if (scanner->info_by_service_protocol.device_name != NULL)
    {
        free (scanner->info_by_service_protocol.device_name);
        scanner->info_by_service_protocol.device_name = NULL;
    }

    if (scanner != NULL)
    {
        free (scanner);
        scanner = NULL;
    }
}
rf627_old_profile2D_t* rf627_old_get_profile2D(rf627_old_t* scanner, rfBool zero_points)
{

    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);

    rfInt nret = network_platform.network_methods.recv_data(
                scanner->m_data_sock, RX, RX_SIZE);
    if(nret > 0)
    {
        rfSize profile_header_size =
                rf627_protocol_old_get_size_of_response_profile_header_packet();

        rf627_old_profile2D_t* profile =
                memory_platform.rf_calloc(1, sizeof(rf627_old_profile2D_t));

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

        if(profile->header.serial_number == scanner->factory_params.general.serial)
        {
            rfInt16 x;
            rfUint16 z;

            rfUint32 pt_count;
            switch (profile->header.data_type)
            {
            case DTY_PixelsNormal:
                pt_count = RF627_PROFILE_SIZE;
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
                pt_count = RF627_PROFILE_SIZE;
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
                pt_count = RF627_EXT_PROFILE_SIZE;
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
                pt_count = RF627_EXT_PROFILE_SIZE;
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
                        pt.x = (rfDouble)(x) * (rfDouble)(profile->header.xemr) /
                                (rfDouble)(profile->header.discrete_value);
                        pt.z = (rfDouble)(z) * (rfDouble)(profile->header.zmr) /
                                (rfDouble)(profile->header.discrete_value);

                        profile->profile_format.points[profile->profile_format.points_count] = pt;
                        profile->profile_format.points_count++;
                        if (profile->header.flags & 0x01)
                        {
                            profile->intensity[profile->intensity_count] = RX[profile_header_size + pt_count*4 + i];
                            profile->intensity_count++;
                        }
                    }else if(zero_points != 0)
                    {
                        pt.x = (rfDouble)(x) * (rfDouble)(profile->header.xemr) /
                                (rfDouble)(profile->header.discrete_value);
                        pt.z = (rfDouble)(z) * (rfDouble)(profile->header.zmr) /
                                (rfDouble)(profile->header.discrete_value);

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
        }
    }
    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);
    return NULL;
}

rf627_old_profile3D_t* rf627_old_get_profile3D(rf627_old_t* scanner, rfFloat step_size, rfFloat k,
                                               count_types_t count_type,
                                               rfBool zero_points,
                                               protocol_types_t protocol)
{

    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);

    rfInt nret = network_platform.network_methods.recv_data(
                scanner->m_data_sock, RX, RX_SIZE);

    if(nret > 0)
    {
        rfSize profile_header_size =
                rf627_protocol_old_get_size_of_response_profile_header_packet();

        rf627_old_profile3D_t* profile =
                memory_platform.rf_calloc(1, sizeof(rf627_old_profile3D_t));

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

        if(profile->header.serial_number == scanner->factory_params.general.serial)
        {
            rfInt16 x;
            rfUint16 z;

            rfUint32 pt_count;
            switch (profile->header.data_type)
            {
            case DTY_PixelsNormal:
                pt_count = RF627_PROFILE_SIZE;
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
                pt_count = RF627_PROFILE_SIZE;
                profile->profile_format.points_count = 0;
                profile->profile_format.points =
                        memory_platform.rf_calloc(pt_count, sizeof (rf627_old_point3D_t));
                if (profile->header.flags & 0x01){
                    profile->intensity_count = 0;
                    profile->intensity =
                            memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                }
                break;
            case DTY_PixelsInterpolated:
                pt_count = RF627_EXT_PROFILE_SIZE;
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
                pt_count = RF627_EXT_PROFILE_SIZE;
                profile->profile_format.points_count = 0;
                profile->profile_format.points =
                        memory_platform.rf_calloc(pt_count, sizeof (rf627_old_point3D_t));
                if (profile->header.flags & 0x01){
                    profile->intensity_count = 0;
                    profile->intensity =
                            memory_platform.rf_calloc(pt_count, sizeof (rfUint8));
                }
                break;
            }

            for (rfUint32 i=0; i<pt_count; i++)
            {
                rf627_old_point3D_t pt;
                switch (profile->header.data_type)
                {
                case DTY_ProfileNormal:
                case DTY_ProfileInterpolated:
                    x = *(rfInt16*)(&RX[profile_header_size + i*4]);
                    z = *(rfUint16*)(&RX[profile_header_size + i*4 + 2]);
                    if (zero_points == 0 && z > 0 && x != 0)
                    {
                        pt.x = (rfDouble)(x) * (rfDouble)(profile->header.xemr) /
                                (rfDouble)(profile->header.discrete_value);
                        if(count_type == kSTEP)
                            pt.y = k * pt.x + step_size * profile->header.step_count;
                        else if(count_type == kMEASURE)
                            pt.y = k * pt.x + step_size * profile->header.measure_count;
                        pt.z = (rfDouble)(z) * (rfDouble)(profile->header.zmr) /
                                (rfDouble)(profile->header.discrete_value);

                        profile->profile_format.points[profile->profile_format.points_count] = pt;
                        profile->profile_format.points_count++;
                        if (profile->header.flags & 0x01)
                        {
                            profile->intensity[profile->intensity_count] = RX[profile_header_size + pt_count*4 + i];
                            profile->intensity_count++;
                        }
                    }else if(zero_points != 0)
                    {
                        pt.x = (rfDouble)(x) * (rfDouble)(profile->header.xemr) /
                                (rfDouble)(profile->header.discrete_value);
                        if(count_type == kSTEP)
                            pt.y = k * pt.x + step_size * profile->header.step_count;
                        else if(count_type == kMEASURE)
                            pt.y = k * pt.x + step_size * profile->header.measure_count;
                        pt.z = (rfDouble)(z) * (rfDouble)(profile->header.zmr) /
                                (rfDouble)(profile->header.discrete_value);

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
        }
    }
    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);
    return NULL;


//    if (nret < msg_size) {
//        //dprint("get_result!");
//        //_mx[1].unlock();
//        return NULL;
//    }

//    if (profile_header.data_type < DTY_PixelsNormal || msg->data_type > DTY_ProfileInterpolated) {
//        //_mx[1].unlock();
//        return NULL;
//    }



}


parameter_t* create_parameter_from_type(const rfChar* type)
{
    parameter_t* p = NULL;
    if(rf_strcmp("uint32_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->val_uint32 = memory_platform.rf_calloc(1, sizeof (value_uint32_t));
        p->base.type = "uint32_t";
//        rfUint16 len = rf_strlen(type) + 1;
//        p->base.type = memory_platform.rf_calloc(1, sizeof(rfChar) * len);
//        memory_platform.rf_memcpy((void*)p->base.type, type, len);
    }else if(rf_strcmp("uint64_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->val_uint64 = memory_platform.rf_calloc(1, sizeof (value_uint64_t));
        p->base.type = "uint64_t";
    }else if(rf_strcmp("int32_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->val_int32 = memory_platform.rf_calloc(1, sizeof (value_uint32_t));
        p->base.type = "int32_t";
    }else if(rf_strcmp("int64_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->val_int64 = memory_platform.rf_calloc(1, sizeof (value_int64_t));
        p->base.type = "int64_t";
    }else if(rf_strcmp("float_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->val_flt = memory_platform.rf_calloc(1, sizeof (value_flt_t));
        p->base.type = "float_t";
    }else if(rf_strcmp("double_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->val_dbl = memory_platform.rf_calloc(1, sizeof (value_dbl_t));
        p->base.type = "double_t";
    }else if(rf_strcmp("u32_arr_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->arr_uint32 = memory_platform.rf_calloc(1, sizeof (array_uint32_t));
        p->base.type = "u32_arr_t";
    }else if(rf_strcmp("u64_arr_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->arr_uint64 = memory_platform.rf_calloc(1, sizeof (array_uint64_t));
        p->base.type = "u64_arr_t";
    }else if(rf_strcmp("i32_arr_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->arr_int32 = memory_platform.rf_calloc(1, sizeof (array_int32_t));
        p->base.type = "i32_arr_t";
    }else if(rf_strcmp("i64_arr_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->arr_int64 = memory_platform.rf_calloc(1, sizeof (array_int64_t));
        p->base.type = "i64_arr_t";
    }else if(rf_strcmp("flt_array_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->arr_flt = memory_platform.rf_calloc(1, sizeof (array_flt_t));
        p->base.type = "flt_array_t";
    }else if(rf_strcmp("dbl_array_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->arr_dbl = memory_platform.rf_calloc(1, sizeof (array_dbl_t));
        p->base.type = "dbl_array_t";
    }else if(rf_strcmp("string_t", type) == 0)
    {
        p = memory_platform.rf_calloc(1, sizeof (parameter_t));
        p->val_str = memory_platform.rf_calloc(1, sizeof (value_str_t));
        p->base.type = "string_t";
    }
    return p;
}

rfInt* get_value_by_key_from_enum(valuesEnum_t* values_enum, char* key)
{
    rfInt* result = NULL;
    for (rfInt32 idx = 0; idx < values_enum->recCount; idx++)
    {
        if (rf_strcmp(values_enum->rec[idx].key, key) == 0)
        {
            result = &values_enum->rec[idx].value;
        }
    }
    return result;
}

rfBool set_value_by_key(parameter_t* p, char* key)
{
    if (rf_strcmp("int32_t", p->base.type))
    {
        for (rfInt32 idx = 0; idx < p->val_int32->enumValues->recCount; idx++)
        {
            if (rf_strcmp(p->val_int32->enumValues->rec[idx].key, key) == 0)
            {
                p->val_int32->value = p->val_int32->enumValues->rec[idx].value;
                return 0;
            }
        }
    }else
    if (rf_strcmp("uint32_t", p->base.type))
    {
        for (rfInt32 idx = 0; idx < p->val_uint32->enumValues->recCount; idx++)
        {
            if (rf_strcmp(p->val_uint32->enumValues->rec[idx].key, key) == 0)
            {
                p->val_uint32->value = p->val_uint32->enumValues->rec[idx].value;
                return 0;
            }
        }
    }else
    if (rf_strcmp("int64_t", p->base.type))
    {
        for (rfInt32 idx = 0; idx < p->val_int64->enumValues->recCount; idx++)
        {
            if (rf_strcmp(p->val_int64->enumValues->rec[idx].key, key) == 0)
            {
                p->val_int64->value = p->val_int64->enumValues->rec[idx].value;
                return 0;
            }
        }
    }else
    if (rf_strcmp("uint64_t", p->base.type))
    {
        for (rfInt32 idx = 0; idx < p->val_uint64->enumValues->recCount; idx++)
        {
            if (rf_strcmp(p->val_uint64->enumValues->rec[idx].key, key) == 0)
            {
                p->val_uint64->value = p->val_uint64->enumValues->rec[idx].value;
                return 0;
            }
        }
    }

    return 1;
}

enum ParamEnumType
{
    kBoolEnum,
    kFlipEnum,
    kRoiPosModeEnum,
    kNetSpeedEnum,
    kStreamsFormatEnum,
    kProcessingModeEnum,
    kMedianFilterEnum,
    kBilateralFilterEnum,
    kPeakModeEnum,
    kLaserModeEnum,
    kInput1EventEnum,
    kInput1ModeEnum,
    kInput2ModeEnum,
    kInput3ModeEnum,
    kOutputModeEnum,
    kMotionTypeEnum,
    kYSourceEnum,
    kPaintModeEnum
};

valuesEnum_t* createParamEnum(enum ParamEnumType enum_type)
{
    switch (enum_type) {
    case kBoolEnum:
    {
        char* key;
        char* label;
        int enum_index;

        valuesEnum_t* boolEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        boolEnum->recCount = 2;
        boolEnum->rec =  memory_platform.rf_calloc(boolEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "false";
        label = "false";
        boolEnum->rec[enum_index].value = 0;
        boolEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(boolEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        boolEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(boolEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "true";
        label = "true";
        boolEnum->rec[enum_index].value = 0;
        boolEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(boolEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        boolEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(boolEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        return boolEnum;
    }
    case kFlipEnum:
    {
        char* key;
        char* label;
        int enum_index;

        valuesEnum_t* flipEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        flipEnum->recCount = 4;
        flipEnum->rec =  memory_platform.rf_calloc(flipEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "No";
        label = "No";
        flipEnum->rec[enum_index].value = FM_NO;
        flipEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(flipEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        flipEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(flipEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "X";
        label = "X";
        flipEnum->rec[enum_index].value = FM_X;
        flipEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(flipEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        flipEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(flipEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Z";
        label = "Z";
        flipEnum->rec[enum_index].value = FM_Z;
        flipEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(flipEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        flipEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(flipEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "XZ";
        label = "XZ";
        flipEnum->rec[enum_index].value = FM_XZ;
        flipEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(flipEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        flipEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(flipEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        return flipEnum;
    }
    case kRoiPosModeEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* roiPosModeEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        roiPosModeEnum->recCount = 2;
        roiPosModeEnum->rec =  memory_platform.rf_calloc(roiPosModeEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "manual";
        label = "manual";
        roiPosModeEnum->rec[enum_index].value = RPM_MANUAL;
        roiPosModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(roiPosModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        roiPosModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(roiPosModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "auto";
        label = "auto";
        roiPosModeEnum->rec[enum_index].value = RPM_AUTO;
        roiPosModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(roiPosModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        roiPosModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(roiPosModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        return roiPosModeEnum;
    }
    case kNetSpeedEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* netSpeedEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        netSpeedEnum->recCount = 3;
        netSpeedEnum->rec =  memory_platform.rf_calloc(netSpeedEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "10";
        label = "10";
        netSpeedEnum->rec[enum_index].value = LS_10MBIT;
        netSpeedEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(netSpeedEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        netSpeedEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(netSpeedEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "100";
        label = "100";
        netSpeedEnum->rec[enum_index].value = LS_100MBIT;
        netSpeedEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(netSpeedEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        netSpeedEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(netSpeedEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "1000";
        label = "1000";
        netSpeedEnum->rec[enum_index].value = LS_1GBIT;
        netSpeedEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(netSpeedEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        netSpeedEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(netSpeedEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        return netSpeedEnum;
    }
    case kStreamsFormatEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* streamsFormatEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        streamsFormatEnum->recCount = 4;
        streamsFormatEnum->rec =  memory_platform.rf_calloc(streamsFormatEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "PIXELS";
        label = "Pixels";
        streamsFormatEnum->rec[enum_index].value = DF_PIXELS;
        streamsFormatEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(streamsFormatEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        streamsFormatEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(streamsFormatEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "PROFILE";
        label = "Profile";
        streamsFormatEnum->rec[enum_index].value = DF_PROFILE;
        streamsFormatEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(streamsFormatEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        streamsFormatEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(streamsFormatEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "PIXELS_INTRP";
        label = "Interpolated pixels";
        streamsFormatEnum->rec[enum_index].value = DF_PIXELS_INTRP;
        streamsFormatEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(streamsFormatEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        streamsFormatEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(streamsFormatEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "PROFILE_INTRP";
        label = "Interpolated profile";
        streamsFormatEnum->rec[enum_index].value = DF_PROFILE_INTRP;
        streamsFormatEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(streamsFormatEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        streamsFormatEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(streamsFormatEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        return streamsFormatEnum;
    }
    case kProcessingModeEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* processingModeEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        processingModeEnum->recCount = 2;
        processingModeEnum->rec =  memory_platform.rf_calloc(processingModeEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "High accuracy";
        label = "High accuracy";
        processingModeEnum->rec[enum_index].value = PM_ACCURACY;
        processingModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(processingModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        processingModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(processingModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Welding";
        label = "Welding";
        processingModeEnum->rec[enum_index].value = PM_WELDING;
        processingModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(processingModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        processingModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(processingModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;
        return processingModeEnum;
    }
    case kMedianFilterEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* medianFilterEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        medianFilterEnum->recCount = 8;
        medianFilterEnum->rec =  memory_platform.rf_calloc(medianFilterEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "0";
        label = "0";
        medianFilterEnum->rec[enum_index].value = 0;
        medianFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        medianFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "3";
        label = "3";
        medianFilterEnum->rec[enum_index].value = 3;
        medianFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        medianFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "5";
        label = "5";
        medianFilterEnum->rec[enum_index].value = 5;
        medianFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        medianFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "7";
        label = "7";
        medianFilterEnum->rec[enum_index].value = 7;
        medianFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        medianFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "9";
        label = "9";
        medianFilterEnum->rec[enum_index].value = 9;
        medianFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        medianFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "11";
        label = "11";
        medianFilterEnum->rec[enum_index].value = 11;
        medianFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        medianFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "13";
        label = "13";
        medianFilterEnum->rec[enum_index].value = 13;
        medianFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        medianFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "15";
        label = "15";
        medianFilterEnum->rec[enum_index].value = 15;
        medianFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        medianFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(medianFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        return medianFilterEnum;
    }
    case kBilateralFilterEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* bilateralFilterEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        bilateralFilterEnum->recCount = 8;
        bilateralFilterEnum->rec =  memory_platform.rf_calloc(bilateralFilterEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "0";
        label = "0";
        bilateralFilterEnum->rec[enum_index].value = 0;
        bilateralFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        bilateralFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "3";
        label = "3";
        bilateralFilterEnum->rec[enum_index].value = 3;
        bilateralFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        bilateralFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "5";
        label = "5";
        bilateralFilterEnum->rec[enum_index].value = 5;
        bilateralFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        bilateralFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "7";
        label = "7";
        bilateralFilterEnum->rec[enum_index].value = 7;
        bilateralFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        bilateralFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "9";
        label = "9";
        bilateralFilterEnum->rec[enum_index].value = 9;
        bilateralFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        bilateralFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "11";
        label = "11";
        bilateralFilterEnum->rec[enum_index].value = 11;
        bilateralFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        bilateralFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "13";
        label = "13";
        bilateralFilterEnum->rec[enum_index].value = 13;
        bilateralFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        bilateralFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "15";
        label = "15";
        bilateralFilterEnum->rec[enum_index].value = 15;
        bilateralFilterEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        bilateralFilterEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(bilateralFilterEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        return bilateralFilterEnum;
    }
    case kPeakModeEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* peakModeEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        peakModeEnum->recCount = 8;
        peakModeEnum->rec =  memory_platform.rf_calloc(peakModeEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "Max intensity";
        label = "Max intensity";
        peakModeEnum->rec[enum_index].value = PM_MAX_INTENSITY;
        peakModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        peakModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "First";
        label = "First";
        peakModeEnum->rec[enum_index].value = PM_FIRST;
        peakModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        peakModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Last";
        label = "Last";
        peakModeEnum->rec[enum_index].value = PM_LAST;
        peakModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        peakModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "#2";
        label = "#2";
        peakModeEnum->rec[enum_index].value = PM_NUMBER_2;
        peakModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        peakModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "#3";
        label = "#3";
        peakModeEnum->rec[enum_index].value = PM_NUMBER_3;
        peakModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        peakModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "#4";
        label = "#4";
        peakModeEnum->rec[enum_index].value = PM_NUMBER_4;
        peakModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        peakModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "#5";
        label = "#5";
        peakModeEnum->rec[enum_index].value = PM_NUMBER_5;
        peakModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        peakModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "#6";
        label = "#6";
        peakModeEnum->rec[enum_index].value = PM_NUMBER_6;
        peakModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        peakModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(peakModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;
        return peakModeEnum;
    }
    case kLaserModeEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* laserModeEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        laserModeEnum->recCount = 2;
        laserModeEnum->rec =  memory_platform.rf_calloc(laserModeEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "Always on";
        label = "Always on";
        laserModeEnum->rec[enum_index].value = LASER_ALWAYS_ZERO;
        laserModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(laserModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        laserModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(laserModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Expose sync";
        label = "Expose sync";
        laserModeEnum->rec[enum_index].value = LASER_STROBE_INV;
        laserModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(laserModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        laserModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(laserModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        return laserModeEnum;
    }
    case kInput1EventEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* input1EventEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        input1EventEnum->recCount = 3;
        input1EventEnum->rec =  memory_platform.rf_calloc(input1EventEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "Internal generator";
        label = "Internal generator";
        input1EventEnum->rec[enum_index].value = IN1_EVENT_IGEN;
        input1EventEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(input1EventEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        input1EventEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(input1EventEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "External sync";
        label = "External sync";
        input1EventEnum->rec[enum_index].value = IN1_EVENT_EXT;
        input1EventEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(input1EventEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        input1EventEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(input1EventEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Software request";
        label = "Software request";
        input1EventEnum->rec[enum_index].value = IN1_EVENT_SREQ;
        input1EventEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(input1EventEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        input1EventEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(input1EventEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        return input1EventEnum;
    }
    case kInput1ModeEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* input1ModeEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        input1ModeEnum->recCount = 4;
        input1ModeEnum->rec =  memory_platform.rf_calloc(input1ModeEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "Rise";
        label = "Rise";
        input1ModeEnum->rec[enum_index].value = IN1_MODE_RISE;
        input1ModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(input1ModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        input1ModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(input1ModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Fall";
        label = "Fall";
        input1ModeEnum->rec[enum_index].value = IN1_MODE_FALL;
        input1ModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(input1ModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        input1ModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(input1ModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "High level";
        label = "High level";
        input1ModeEnum->rec[enum_index].value = IN1_MODE_LVL1;
        input1ModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(input1ModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        input1ModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(input1ModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Low level";
        label = "Low level";
        input1ModeEnum->rec[enum_index].value = IN1_MODE_LVL0;
        input1ModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(input1ModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        input1ModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(input1ModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;
        return input1ModeEnum;
    }
    case kInput2ModeEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* input2ModeEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        input2ModeEnum->recCount = 2;
        input2ModeEnum->rec =  memory_platform.rf_calloc(input2ModeEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "Level";
        label = "Level";
        input2ModeEnum->rec[enum_index].value = IN2_MODE_LVL;
        input2ModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(input2ModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        input2ModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(input2ModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Phase";
        label = "Phase";
        input2ModeEnum->rec[enum_index].value = IN2_MODE_PHASE;
        input2ModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(input2ModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        input2ModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(input2ModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        return input2ModeEnum;
    }
    case kInput3ModeEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* input3ModeEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        input3ModeEnum->recCount = 2;
        input3ModeEnum->rec =  memory_platform.rf_calloc(input3ModeEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "Rise";
        label = "Rise";
        input3ModeEnum->rec[enum_index].value = IN3_MODE_RISE;
        input3ModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(input3ModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        input3ModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(input3ModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Fall";
        label = "Fall";
        input3ModeEnum->rec[enum_index].value = IN3_MODE_FALL;
        input3ModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(input3ModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        input3ModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(input3ModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;
        return input3ModeEnum;
    }
    case kOutputModeEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* outputModeEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        outputModeEnum->recCount = 11;
        outputModeEnum->rec =  memory_platform.rf_calloc(outputModeEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "Exposure start";
        label = "Exposure start";
        outputModeEnum->rec[enum_index].value = OUT_MODE_EXP_START;
        outputModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        outputModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "In1 level";
        label = "In1 level";
        outputModeEnum->rec[enum_index].value = OUT_MODE_IN1_LOG_LVL;
        outputModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        outputModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "In1 rise";
        label = "In1 rise";
        outputModeEnum->rec[enum_index].value = OUT_MODE_IN1_RISE;
        outputModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        outputModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "In1 fall";
        label = "In1 fall";
        outputModeEnum->rec[enum_index].value = OUT_MODE_IN1_FALL;
        outputModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        outputModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "In2 level";
        label = "In2 level";
        outputModeEnum->rec[enum_index].value = OUT_MODE_IN2_LOG_LVL;
        outputModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        outputModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "In2 rise";
        label = "In2 rise";
        outputModeEnum->rec[enum_index].value = OUT_MODE_IN2_RISE;
        outputModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        outputModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "In2 fall";
        label = "In2 fall";
        outputModeEnum->rec[enum_index].value = OUT_MODE_IN2_FALL;
        outputModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        outputModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "In3 level";
        label = "In3 level";
        outputModeEnum->rec[enum_index].value = OUT_MODE_IN3_LOG_LVL;
        outputModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        outputModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "In3 rise";
        label = "In3 rise";
        outputModeEnum->rec[enum_index].value = OUT_MODE_IN3_RISE;
        outputModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        outputModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "In3 fall";
        label = "In3 fall";
        outputModeEnum->rec[enum_index].value = OUT_MODE_IN3_FALL;
        outputModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        outputModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Exposure time";
        label = "Exposure time";
        outputModeEnum->rec[enum_index].value = OUT_MODE_EXP_TIME;
        outputModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        outputModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(outputModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;
        return outputModeEnum;
    }
    case kMotionTypeEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* motionTypeEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        motionTypeEnum->recCount = 2;
        motionTypeEnum->rec =  memory_platform.rf_calloc(motionTypeEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "Linear";
        label = "Linear";
        motionTypeEnum->rec[enum_index].value = 0;
        motionTypeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(motionTypeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        motionTypeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(motionTypeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Radial";
        label = "Radial";
        motionTypeEnum->rec[enum_index].value = 1;
        motionTypeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(motionTypeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        motionTypeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(motionTypeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;
        return motionTypeEnum;
    }
    case kYSourceEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* ySourceEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        ySourceEnum->recCount = 3;
        ySourceEnum->rec =  memory_platform.rf_calloc(ySourceEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "System time";
        label = "System time";
        ySourceEnum->rec[enum_index].value = YA_SYSTEM_TIME;
        ySourceEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(ySourceEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        ySourceEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(ySourceEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Step counter";
        label = "Step counter";
        ySourceEnum->rec[enum_index].value = YA_STEP_COUNTER;
        ySourceEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(ySourceEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        ySourceEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(ySourceEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Measures counter";
        label = "Measures counter";
        ySourceEnum->rec[enum_index].value = YA_MEASURES_COUNTER;
        ySourceEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(ySourceEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        ySourceEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(ySourceEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        return ySourceEnum;
    }
    case kPaintModeEnum:
    {
        char* key;
        char* label;
        int enum_index;
        valuesEnum_t* paintModeEnum = memory_platform.rf_calloc(1, sizeof(valuesEnum_t));
        paintModeEnum->recCount = 2;
        paintModeEnum->rec =  memory_platform.rf_calloc(paintModeEnum->recCount, sizeof(enumRec_t));
        enum_index = 0;

        key = "Heightmap";
        label = "Heightmap";
        paintModeEnum->rec[enum_index].value = 0;
        paintModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(paintModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        paintModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(paintModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;

        key = "Intensity";
        label = "Intensity";
        paintModeEnum->rec[enum_index].value = 1;
        paintModeEnum->rec[enum_index].key = memory_platform.rf_calloc(1, rf_strlen(key) + 1);
        memory_platform.rf_memcpy(paintModeEnum->rec[enum_index].key, key, rf_strlen(key) + 1);
        paintModeEnum->rec[enum_index].label = memory_platform.rf_calloc(1, rf_strlen(label) + 1);
        memory_platform.rf_memcpy(paintModeEnum->rec[enum_index].label, label, rf_strlen(label) + 1);
        enum_index++;
        return paintModeEnum;
    }
    default:
        break;
    }
}

void set_str(rfChar** dst_str, rfChar* src_str)
{
    rfUint32 src_str_size = rf_strlen(src_str) + 1;
    *dst_str = memory_platform.rf_calloc(1, sizeof(rfChar) * src_str_size);
    memory_platform.rf_memcpy(*dst_str, src_str, src_str_size);
}

rfBool rf627_old_read_user_params_from_scanner(rf627_old_t* scanner)
{

    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);


    rfUint32 dst_ip_addr;
    rfUint16 dst_port;
    rfBool ret = 0;

    //std::cout << __LINE__ << " _mx[0].lock();" << std::endl << std::flush;
    //_mx[0].lock();

    // create read_params msg request
    rf627_old_header_msg_t read_user_params_msg =
            rf627_protocol_old_create_read_user_params_msg_request(
                kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_ON,
                scanner->factory_params.general.serial,
                scanner->msg_count);

    // pack hello msg request to packet
    rfUint32 request_packet_size =
            rf627_protocol_old_pack_read_user_params_msg_request_to_packet(
                (rfUint8*)TX, TX_SIZE, &read_user_params_msg);

    //send_addr.sin_family = RF_AF_INET;
    dst_ip_addr = scanner->user_params.network.ip_address[0] << 24 |
                  scanner->user_params.network.ip_address[1] << 16 |
                  scanner->user_params.network.ip_address[2] << 8 |
                  scanner->user_params.network.ip_address[3];
    dst_port = scanner->user_params.network.service_port;



    if (rf627_protocol_send_packet_by_udp(
                scanner->m_svc_sock, TX, request_packet_size, dst_ip_addr, dst_port, 0, NULL))
    {
        scanner->msg_count++;
        const rfInt data_len =
                rf627_protocol_old_get_size_of_response_read_user_params_packet();
        rfInt nret = network_platform.network_methods.recv_data(
                    scanner->m_svc_sock, RX, data_len);
        if (nret == data_len)
        {
            rfSize confirm_packet_size =
                    rf627_protocol_old_create_confirm_packet_from_response_packet(
                        TX, TX_SIZE, RX, RX_SIZE);
            if(confirm_packet_size > 0)
            {
                rf627_protocol_send_packet_by_udp(
                            scanner->m_svc_sock, TX, confirm_packet_size, dst_ip_addr, dst_port, 0, 0);
            }

            rf627_old_header_msg_t header =
                    rf627_protocol_old_unpack_header_msg_from_user_params_packet(RX);

            if(header.serial_number == scanner->factory_params.general.serial)
            {
                rf627_old_user_params_msg_t user_param_msg =
                        rf627_protocol_old_unpack_payload_msg_from_user_params_packet(RX);

                scanner->user_params = *(rf627_old_user_params_t*)&user_param_msg;


                rfUint16 index = 0;
                parameter_t* p = create_parameter_from_type("string_t");
                set_str(&p->base.name, "user_general_deviceName");
                set_str(&p->base.access, "write");
                set_str(&p->base.units,"");
                p->base.index = index++;
                p->base.offset = 0;
                p->base.size = rf_strlen(scanner->user_params.general.name) + 1;

                p->val_str->value = memory_platform.rf_calloc(1, sizeof(rfChar) * p->base.size);
                memory_platform.rf_memcpy(
                            (void*)p->val_str->value,
                            scanner->user_params.general.name,
                            p->base.size);
                p->val_str->maxLen = sizeof (scanner->user_params.general.name);
                set_str(&p->val_str->defValue, "SERVICE CONFIGURATION, contact with manufacturer");
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_general_logSaveEnabled");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 64;
                p->base.size = sizeof(scanner->user_params.general.save_log_to_spi);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.general.save_log_to_spi;
                p->val_uint32->min = 0;
                p->val_uint32->max = 0;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                rfInt* def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_fpgaTemp");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 192;
                p->base.size = sizeof(scanner->user_params.sysmon.fpga_temp);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.fpga_temp;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_sysMon_paramsChanged");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 194;
                p->base.size = sizeof(scanner->user_params.sysmon.params_changed);
                set_str(&p->base.units, "°C");

                p->val_uint32->value = scanner->user_params.sysmon.params_changed;
                p->val_uint32->min = 0;
                p->val_uint32->max = 7;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens00");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 195;
                p->base.size = sizeof(scanner->user_params.sysmon.sens00_temp);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens00_temp;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens00Max");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 197;
                p->base.size = sizeof(scanner->user_params.sysmon.sens00_max);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens00_max;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens00Min");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 199;
                p->base.size = sizeof(scanner->user_params.sysmon.sens00_min);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens00_min;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens01");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 201;
                p->base.size = sizeof(scanner->user_params.sysmon.sens01_temp);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens01_temp;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens01Max");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 203;
                p->base.size = sizeof(scanner->user_params.sysmon.sens01_max);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens01_max;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens01Min");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 205;
                p->base.size = sizeof(scanner->user_params.sysmon.sens01_min);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens01_min;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens10");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 207;
                p->base.size = sizeof(scanner->user_params.sysmon.sens10_temp);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens10_temp;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens10Max");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 209;
                p->base.size = sizeof(scanner->user_params.sysmon.sens10_max);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens10_max;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens10Min");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 211;
                p->base.size = sizeof(scanner->user_params.sysmon.sens10_min);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens10_min;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens11");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 213;
                p->base.size = sizeof(scanner->user_params.sysmon.sens11_temp);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens11_temp;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens11Max");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 215;
                p->base.size = sizeof(scanner->user_params.sysmon.sens11_max);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens11_max;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("float_t");
                set_str(&p->base.name, "user_sysMon_tempSens11Min");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 217;
                p->base.size = sizeof(scanner->user_params.sysmon.sens11_min);
                set_str(&p->base.units, "°C");

                p->val_flt->value = scanner->user_params.sysmon.sens11_min;
                p->val_flt->min = -100;
                p->val_flt->max = 150;
                p->val_flt->step = 0;
                p->val_flt->defValue = 0;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_compatibility_rf625enabled");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 274;
                p->base.size = sizeof(scanner->user_params.rf625compat.enable);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.rf625compat.enable;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);


                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_compatibility_rf625TcpPort");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 275;
                p->base.size = sizeof(scanner->user_params.rf625compat.tcp_port);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.rf625compat.tcp_port;
                p->val_uint32->min = 0;
                p->val_uint32->max = 65535;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 620;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_sensor_doubleSpeedEnabled");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 309;
                p->base.size = sizeof(scanner->user_params.sensor.dhs);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.sensor.dhs;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);


                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_analogGain");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 310;
                p->base.size = sizeof(scanner->user_params.sensor.gain_analog);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.sensor.gain_analog;
                p->val_uint32->min = 0;
                p->val_uint32->max = 7;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 2;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_digitalGain");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 311;
                p->base.size = sizeof(scanner->user_params.sensor.gain_digital);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.sensor.gain_digital;
                p->val_uint32->min = 0;
                p->val_uint32->max = 63;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 48;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_sensor_exposure1");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 312;
                p->base.size = sizeof(scanner->user_params.sensor.exposure);
                set_str(&p->base.units, "ns");

                p->val_uint32->value = scanner->user_params.sensor.exposure;
                p->val_uint32->min = 3000;
                p->val_uint32->max = 300000000;
                p->val_uint32->step = 100;
                p->val_uint32->defValue = 300000;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_sensor_maxExposure");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 316;
                p->base.size = sizeof(scanner->user_params.sensor.max_exposure);
                set_str(&p->base.units, "ns");

                p->val_uint32->value = scanner->user_params.sensor.max_exposure;
                p->val_uint32->min = 3000;
                p->val_uint32->max = 2147483647;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 1443298;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_sensor_framerate");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 320;
                p->base.size = sizeof(scanner->user_params.sensor.frame_rate);
                set_str(&p->base.units, "Hz");

                p->val_uint32->value = scanner->user_params.sensor.frame_rate;
                p->val_uint32->min = 0;
                p->val_uint32->max = 20000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 485;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_sensor_maxFramerate");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 324;
                p->base.size = sizeof(scanner->user_params.sensor.max_frame_rate);
                set_str(&p->base.units, "Hz");

                p->val_uint32->value = scanner->user_params.sensor.max_frame_rate;
                p->val_uint32->min = 0;
                p->val_uint32->max = 20000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 485;
                vector_add(scanner->params_list, p);


                // exposure_hdr_mode


                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_sensor_exposureControl");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 329;
                p->base.size = sizeof(scanner->user_params.sensor.auto_exposure);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.sensor.auto_exposure;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_sensor_edrType");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 330;
                p->base.size = sizeof(scanner->user_params.sensor.column_edr_mode);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.sensor.column_edr_mode;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_sensor_edrColumnDivider");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 331;
                p->base.size = sizeof(scanner->user_params.sensor.column_exposure_div);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.sensor.column_exposure_div;
                p->val_uint32->min = 1;
                p->val_uint32->max = scanner->user_params.sensor.column_exposure_max_div;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 1;
                vector_add(scanner->params_list, p);


                //roi
                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_roi_enabled");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 392;
                p->base.size = sizeof(scanner->user_params.roi.enable);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.roi.enable;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_roi_active");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 393;
                p->base.size = sizeof(scanner->user_params.roi.active);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.roi.active;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_roi_size");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 394;
                p->base.size = sizeof(scanner->user_params.roi.size);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.roi.size;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1024;
                p->val_uint32->step = 8;
                p->val_uint32->defValue = 64;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_roi_posMode");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 396;
                p->base.size = sizeof(scanner->user_params.roi.position_mode);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.roi.position_mode;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_roi_pos");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 397;
                p->base.size = sizeof(scanner->user_params.roi.manual_position);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.roi.manual_position;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1280;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 100;
                vector_add(scanner->params_list, p);

                //auto_position

                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_roi_reqProfSize");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 401;
                p->base.size = sizeof(scanner->user_params.roi.required_profile_size);
                set_str(&p->base.units, "points");

                p->val_uint32->value = scanner->user_params.roi.required_profile_size;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1280;
                p->val_uint32->step = 64;
                p->val_uint32->defValue = 320;
                vector_add(scanner->params_list, p);


                //network
                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_network_speed");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 483;
                p->base.size = sizeof(scanner->user_params.network.speed);
                set_str(&p->base.units, "points");

                p->val_uint32->value = scanner->user_params.network.speed;
                p->val_uint32->min = 10;
                p->val_uint32->max = 1000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 1000;
                p->val_uint32->enumValues = createParamEnum(kNetSpeedEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "1000");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_network_autoNeg");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 485;
                p->base.size = sizeof(scanner->user_params.network.autonegotiation);
                set_str(&p->base.units, "points");

                p->val_uint32->value = scanner->user_params.network.autonegotiation;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 1;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "true");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);




                p = create_parameter_from_type("u32_arr_t");
                set_str(&p->base.name, "user_network_ip");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 486;
                p->base.size = sizeof(scanner->user_params.network.ip_address);
                set_str(&p->base.units, "");

                p->arr_uint32->value = memory_platform.rf_calloc(1, sizeof(rfUint32) * 4);
                for (rfUint32 i = 0; i < p->base.size; i++)
                    p->arr_uint32->value[i] = scanner->user_params.network.ip_address[i];
                p->arr_uint32->min = 0;
                p->arr_uint32->max = 255;
                p->arr_uint32->step = 0;
                p->arr_uint32->defCount = 4;
                p->arr_uint32->defValue = memory_platform.rf_calloc(1, sizeof (rfUint32) * 4);
                rfUint32 IP_arr[4] = {0xC0, 0xA8, 0x01, 0x1E};
                for (rfUint32 i = 0; i < 4; i++)
                    p->arr_uint32->defValue[i] = IP_arr[i];
                p->arr_uint32->maxCount = 4;
                p->arr_uint32->count = 4;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("u32_arr_t");
                set_str(&p->base.name, "user_network_mask");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 490;
                p->base.size = sizeof(scanner->user_params.network.net_mask);
                set_str(&p->base.units, "");

                p->arr_uint32->value = memory_platform.rf_calloc(1, sizeof(rfUint32) * 4);
                for (rfUint32 i = 0; i < p->base.size; i++)
                    p->arr_uint32->value[i] = scanner->user_params.network.net_mask[i];
                p->arr_uint32->min = 0;
                p->arr_uint32->max = 255;
                p->arr_uint32->step = 0;
                p->arr_uint32->defCount = 4;
                p->arr_uint32->defValue = memory_platform.rf_calloc(1, sizeof (rfUint32) * 4);
                rfUint32 MASK_arr[4] = {0xC0, 0xA8, 0x01, 0x1E};
                for (rfUint32 i = 0; i < 4; i++)
                    p->arr_uint32->defValue[i] = MASK_arr[i];
                p->arr_uint32->maxCount = 4;
                p->arr_uint32->count = 4;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("u32_arr_t");
                set_str(&p->base.name, "user_network_gateway");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 494;
                p->base.size = sizeof(scanner->user_params.network.gateway_ip);
                set_str(&p->base.units, "");

                p->arr_uint32->value = memory_platform.rf_calloc(1, sizeof(rfUint32) * 4);
                for (rfUint32 i = 0; i < p->base.size; i++)
                    p->arr_uint32->value[i] = scanner->user_params.network.gateway_ip[i];
                p->arr_uint32->min = 0;
                p->arr_uint32->max = 255;
                p->arr_uint32->step = 0;
                p->arr_uint32->defCount = 4;
                p->arr_uint32->defValue = memory_platform.rf_calloc(1, sizeof (rfUint32) * 4);
                rfUint32 GATEWAY_arr[4] = {0xFF, 0xFF, 0xFF, 0x00};
                for (rfUint32 i = 0; i < 4; i++)
                    p->arr_uint32->defValue[i] = GATEWAY_arr[i];
                p->arr_uint32->maxCount = 4;
                p->arr_uint32->count = 4;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("u32_arr_t");
                set_str(&p->base.name, "user_network_hostIP");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 498;
                p->base.size = sizeof(scanner->user_params.network.host_ip);
                set_str(&p->base.units, "");

                p->arr_uint32->value = memory_platform.rf_calloc(1, sizeof(rfUint32) * 4);
                for (rfUint32 i = 0; i < p->base.size; i++)
                    p->arr_uint32->value[i] = scanner->user_params.network.host_ip[i];
                p->arr_uint32->min = 0;
                p->arr_uint32->max = 255;
                p->arr_uint32->step = 0;
                p->arr_uint32->defCount = 4;
                p->arr_uint32->defValue = memory_platform.rf_calloc(1, sizeof (rfUint32) * 4);
                rfUint32 HOSTIP_arr[4] = {0xC0, 0xA8, 0x01, 0x02};
                for (rfUint32 i = 0; i < 4; i++)
                    p->arr_uint32->defValue[i] = HOSTIP_arr[i];
                p->arr_uint32->maxCount = 4;
                p->arr_uint32->count = 4;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_network_hostPort");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 502;
                p->base.size = sizeof(scanner->user_params.network.stream_port);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.network.stream_port;
                p->val_uint32->min = 0;
                p->val_uint32->max = 65535;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 50001;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_network_webPort");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 504;
                p->base.size = sizeof(scanner->user_params.network.http_port);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.network.http_port;
                p->val_uint32->min = 0;
                p->val_uint32->max = 65535;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 80;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_network_servicePort");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 506;
                p->base.size = sizeof(scanner->user_params.network.service_port);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.network.service_port;
                p->val_uint32->min = 0;
                p->val_uint32->max = 65535;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 50011;
                vector_add(scanner->params_list, p);


                //stream
                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_streams_udpEnabled");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 576;
                p->base.size = sizeof(scanner->user_params.stream.enable);
                set_str(&p->base.units, "points");

                p->val_uint32->value = scanner->user_params.stream.enable;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 1;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_streams_format");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 577;
                p->base.size = sizeof(scanner->user_params.stream.format);
                set_str(&p->base.units, "points");

                p->val_uint32->value = scanner->user_params.stream.format;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 1;
                p->val_uint32->enumValues = createParamEnum(kStreamsFormatEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "Profile");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_streams_includeIntensity");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 579;
                p->base.size = sizeof(scanner->user_params.stream.include_intensivity);
                set_str(&p->base.units, "points");

                p->val_uint32->value = scanner->user_params.stream.include_intensivity;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                //image_processing
                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_processing_threshold");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 611;
                p->base.size = sizeof(scanner->user_params.image_processing.brightness_threshold);
                set_str(&p->base.units, "%");

                p->val_uint32->value = scanner->user_params.image_processing.brightness_threshold;
                p->val_uint32->min = 0;
                p->val_uint32->max = 100;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 10;
                vector_add(scanner->params_list, p);

                //filter_width

//                p = create_parameter_from_type("uint32_t");
//                set_str(&p->base.name, parameter_names[USER_PROCESSING_MODE];
//                set_str(&p->base.access, "write");
//                p->base.index = index++;
//                p->base.offset = 616;
//                p->base.size = sizeof(scanner->user_params.image_processing.processing_mode);
//                set_str(&p->base.units, "");

//                p->val_uint32->value = scanner->user_params.image_processing.processing_mode;
//                p->val_uint32->min = 0;
//                p->val_uint32->max = 1;
//                p->val_uint32->step = 0;
//                p->val_uint32->enumValues = &processingModeEnum;
//                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "High accuracy");
//                if (def != NULL)
//                    p->val_uint32->defValue = *def;
//                else p->val_uint32->defValue = p->val_uint32->value;
//                vector_add(scanner->params_list, p);

                //reduce_noise

                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_processing_profPerSec");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 618;
                p->base.size = sizeof(scanner->user_params.image_processing.frame_rate);
                set_str(&p->base.units, "pps");

                p->val_uint32->value = scanner->user_params.image_processing.frame_rate;
                p->val_uint32->min = 0;
                p->val_uint32->max = 20000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 485;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_processing_medianMode");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 622;
                p->base.size = sizeof(scanner->user_params.image_processing.median_filter_mode);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.image_processing.median_filter_mode;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kMedianFilterEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "Off");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_processing_bilateralMode");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 623;
                p->base.size = sizeof(scanner->user_params.image_processing.bilateral_filter_mode);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.image_processing.bilateral_filter_mode;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kBilateralFilterEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "Off");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_processing_peakMode");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 624;
                p->base.size = sizeof(scanner->user_params.image_processing.peak_select_mode);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.image_processing.peak_select_mode;
                p->val_uint32->min = 0;
                p->val_uint32->max = 7;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kPeakModeEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "Max intensity");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_processing_flip");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 625;
                p->base.size = sizeof(scanner->user_params.image_processing.profile_flip);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.image_processing.profile_flip;
                p->val_uint32->min = 0;
                p->val_uint32->max = 7;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kFlipEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "no");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                //laser
                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_laser_enabled");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 682;
                p->base.size = sizeof(scanner->user_params.laser.enable);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.laser.enable;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



//                p = create_parameter_from_type("uint32_t");
//                set_str(&p->base.name, parameter_names[USER_LASER_ENABLED];
//                set_str(&p->base.access, "write");
//                p->base.index = index++;
//                p->base.offset = 683;
//                p->base.size = sizeof(scanner->user_params.laser.level_mode);
//                set_str(&p->base.units, "");

//                p->val_uint32->value = scanner->user_params.laser.level_mode;
//                p->val_uint32->min = 0;
//                p->val_uint32->max = 1;
//                p->val_uint32->step = 0;
//                p->val_uint32->enumValues = &laserModeEnum;
//                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "Expose sync");
//                if (def != NULL)
//                    p->val_uint32->defValue = *def;
//                else p->val_uint32->defValue = p->val_uint32->value;
//                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_laser_value");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 684;
                p->base.size = sizeof(scanner->user_params.laser.level);
                set_str(&p->base.units, "%");

                p->val_uint32->value = scanner->user_params.laser.level;
                p->val_uint32->min = 0;
                p->val_uint32->max = 100;
                p->val_uint32->step = 5;
                p->val_uint32->defValue = 50;
                vector_add(scanner->params_list, p);


                //inputs
                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_trigger_sync_source");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 718;
                p->base.size = sizeof(scanner->user_params.inputs.preset_index);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.inputs.preset_index;
                p->val_uint32->min = 0;
                p->val_uint32->max = 11;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 0;
                vector_add(scanner->params_list, p);



//                p = create_parameter_from_type("uint32_t");
//                set_str(&p->base.name, parameter_names[USER_INPUTS_PARAMS_MASK];
//                set_str(&p->base.access, "read_only");
//                p->base.index = index++;
//                p->base.offset = 719 + 26*scanner->user_params.inputs.preset_index;
//                p->base.size = sizeof(scanner->user_params.inputs.params[
//                                      scanner->user_params.inputs.preset_index].params_mask);
//                set_str(&p->base.units, "");

//                p->val_uint32->value = scanner->user_params.inputs.params[
//                        scanner->user_params.inputs.preset_index].params_mask;
//                p->val_uint32->min = 0;
//                p->val_uint32->max = 511;
//                p->val_uint32->step = 0;
//                p->val_uint32->defValue = 0;
//                vector_add(scanner->params_list, p);


                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_input1_enabled");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 721 + 26*scanner->user_params.inputs.preset_index;
                p->base.size = sizeof(scanner->user_params.inputs.params[
                                      scanner->user_params.inputs.preset_index].in1_enable);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.inputs.params[
                        scanner->user_params.inputs.preset_index].in1_enable;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_input1_mode");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 722 + 26*scanner->user_params.inputs.preset_index;
                p->base.size = sizeof(scanner->user_params.inputs.params[
                                      scanner->user_params.inputs.preset_index].in1_mode);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.inputs.params[
                        scanner->user_params.inputs.preset_index].in1_mode;
                p->val_uint32->min = 0;
                p->val_uint32->max = 3;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kInput1ModeEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "Rise");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



//                p = create_parameter_from_type("uint32_t");
//                set_str(&p->base.name, parameter_names[USER_INPUTS_1_DELAY];
//                set_str(&p->base.access, "write");
//                p->base.index = index++;
//                p->base.offset = 723 + 26*scanner->user_params.inputs.preset_index;
//                p->base.size = sizeof(scanner->user_params.inputs.params[
//                                      scanner->user_params.inputs.preset_index].in1_delay);
//                set_str(&p->base.units, "ns");

//                p->val_uint32->value = scanner->user_params.inputs.params[
//                        scanner->user_params.inputs.preset_index].in1_delay ;
//                p->val_uint32->min = 30;
//                p->val_uint32->max = 1000000000;
//                p->val_uint32->step = 10;
//                p->val_uint32->defValue = 30;
//                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_input1_samples");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 727 + 26*scanner->user_params.inputs.preset_index;
                p->base.size = sizeof(scanner->user_params.inputs.params[
                                      scanner->user_params.inputs.preset_index].in1_decimation);
                set_str(&p->base.units, "ns");

                p->val_uint32->value = scanner->user_params.inputs.params[
                        scanner->user_params.inputs.preset_index].in1_decimation ;
                p->val_uint32->min = 1;
                p->val_uint32->max = 4096;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = 1;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_input2_enabled");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 728 + 26*scanner->user_params.inputs.preset_index;
                p->base.size = sizeof(scanner->user_params.inputs.params[
                                      scanner->user_params.inputs.preset_index].in2_enable);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.inputs.params[
                        scanner->user_params.inputs.preset_index].in2_enable;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_input2_mode");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 729 + 26*scanner->user_params.inputs.preset_index;
                p->base.size = sizeof(scanner->user_params.inputs.params[
                                      scanner->user_params.inputs.preset_index].in2_mode);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.inputs.params[
                        scanner->user_params.inputs.preset_index].in2_mode;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kInput2ModeEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "Level");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



//                p = create_parameter_from_type("uint32_t");
//                set_str(&p->base.name, parameter_names[USER_INPUTS_2_INVERSE];
//                set_str(&p->base.access, "write");
//                p->base.index = index++;
//                p->base.offset = 730 + 26*scanner->user_params.inputs.preset_index;
//                p->base.size = sizeof(scanner->user_params.inputs.params[
//                                      scanner->user_params.inputs.preset_index].in2_invert);
//                set_str(&p->base.units, "");

//                p->val_uint32->value = scanner->user_params.inputs.params[
//                        scanner->user_params.inputs.preset_index].in2_invert;
//                p->val_uint32->min = 0;
//                p->val_uint32->max = 1;
//                p->val_uint32->step = 0;
//                p->val_uint32->enumValues = &boolEnum;
//                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
//                if (def != NULL)
//                    p->val_uint32->defValue = *def;
//                else p->val_uint32->defValue = p->val_uint32->value;
//                vector_add(scanner->params_list, p);


                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_input3_enabled");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 731 + 26*scanner->user_params.inputs.preset_index;
                p->base.size = sizeof(scanner->user_params.inputs.params[
                                      scanner->user_params.inputs.preset_index].in3_enable);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.inputs.params[
                        scanner->user_params.inputs.preset_index].in3_enable;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name,  "user_input3_mode");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 732 + 26*scanner->user_params.inputs.preset_index;
                p->base.size = sizeof(scanner->user_params.inputs.params[
                                      scanner->user_params.inputs.preset_index].in3_mode);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.inputs.params[
                        scanner->user_params.inputs.preset_index].in3_mode;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kInput3ModeEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "Rise");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);


                //outputs
                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_output1_enabled");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 1063;
                p->base.size = sizeof(scanner->user_params.outputs.out1_enable);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.outputs.out1_enable;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_output1_mode");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 1064;
                p->base.size = sizeof(scanner->user_params.outputs.out1_mode);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.outputs.out1_mode;
                p->val_uint32->min = 0;
                p->val_uint32->max = 10;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kOutputModeEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "Exposure start");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



//                p = create_parameter_from_type("uint32_t");
//                set_str(&p->base.name, parameter_names[USER_OUTPUTS_1_DELAY];
//                set_str(&p->base.access, "write");
//                p->base.index = index++;
//                p->base.offset = 1065;
//                p->base.size = sizeof(scanner->user_params.outputs.out1_delay);
//                set_str(&p->base.units, "ns");

//                p->val_uint32->value = scanner->user_params.outputs.out1_delay ;
//                p->val_uint32->min = 220;
//                p->val_uint32->max = 1000000000;
//                p->val_uint32->step = 10;
//                p->val_uint32->defValue = 220;
//                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_output1_pulseWidth");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 1069;
                p->base.size = sizeof(scanner->user_params.outputs.out1_pulse_width);
                set_str(&p->base.units, "ns");

                p->val_uint32->value = scanner->user_params.outputs.out1_pulse_width ;
                p->val_uint32->min = 10;
                p->val_uint32->max = 10000;
                p->val_uint32->step = 10;
                p->val_uint32->defValue = 10;
                vector_add(scanner->params_list, p);



//                p = create_parameter_from_type("uint32_t");
//                set_str(&p->base.name, parameter_names[USER_OUTPUTS_1_INVERSE];
//                set_str(&p->base.access, "write");
//                p->base.index = index++;
//                p->base.offset = 1073;
//                p->base.size = sizeof(scanner->user_params.outputs.out1_invert);
//                set_str(&p->base.units, "");

//                p->val_uint32->value = scanner->user_params.outputs.out1_invert;
//                p->val_uint32->min = 0;
//                p->val_uint32->max = 1;
//                p->val_uint32->step = 0;
//                p->val_uint32->enumValues = &boolEnum;
//                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
//                if (def != NULL)
//                    p->val_uint32->defValue = *def;
//                else p->val_uint32->defValue = p->val_uint32->value;
//                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name,  "user_output2_enabled");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 1074;
                p->base.size = sizeof(scanner->user_params.outputs.out2_enable);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.outputs.out2_enable;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_output2_mode");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 1075;
                p->base.size = sizeof(scanner->user_params.outputs.out2_mode);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->user_params.outputs.out2_mode;
                p->val_uint32->min = 0;
                p->val_uint32->max = 10;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kOutputModeEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "Exposure start");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



//                p = create_parameter_from_type("uint32_t");
//                set_str(&p->base.name, parameter_names[USER_OUTPUTS_2_DELAY];
//                set_str(&p->base.access, "write");
//                p->base.index = index++;
//                p->base.offset = 1076;
//                p->base.size = sizeof(scanner->user_params.outputs.out2_delay);
//                set_str(&p->base.units, "ns");

//                p->val_uint32->value = scanner->user_params.outputs.out2_delay ;
//                p->val_uint32->min = 220;
//                p->val_uint32->max = 1000000000;
//                p->val_uint32->step = 10;
//                p->val_uint32->defValue = 220;
//                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_output2_pulseWidth");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 1080;
                p->base.size = sizeof(scanner->user_params.outputs.out2_pulse_width);
                set_str(&p->base.units, "ns");

                p->val_uint32->value = scanner->user_params.outputs.out2_pulse_width ;
                p->val_uint32->min = 10;
                p->val_uint32->max = 10000;
                p->val_uint32->step = 10;
                p->val_uint32->defValue = 10;
                vector_add(scanner->params_list, p);



//                p = create_parameter_from_type("uint32_t");
//                set_str(&p->base.name, parameter_names[USER_OUTPUTS_2_INVERSE];
//                set_str(&p->base.access, "write");
//                p->base.index = index++;
//                p->base.offset = 1084;
//                p->base.size = sizeof(scanner->user_params.outputs.out2_invert);
//                set_str(&p->base.units, "");

//                p->val_uint32->value = scanner->user_params.outputs.out2_invert;
//                p->val_uint32->min = 0;
//                p->val_uint32->max = 1;
//                p->val_uint32->step = 0;
//                p->val_uint32->enumValues = boolEnum;
//                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
//                if (def != NULL)
//                    p->val_uint32->defValue = *def;
//                else p->val_uint32->defValue = p->val_uint32->value;
//                vector_add(scanner->params_list, p);

                ret = 1;
            }


        }
    }
//    _mx[0].unlock();

    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);
    return ret;
}

rfBool rf627_old_read_factory_params_from_scanner(rf627_old_t* scanner)
{
    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);


    rfUint32 dst_ip_addr;
    rfUint16 dst_port;
    rfBool ret = FALSE;

    //std::cout << __LINE__ << " _mx[0].lock();" << std::endl << std::flush;
    //_mx[0].lock();

    // create read_params msg request
    rf627_old_header_msg_t read_factory_params_msg =
            rf627_protocol_old_create_read_factory_params_msg_request(
                kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_ON,
                scanner->factory_params.general.serial,
                scanner->msg_count);

    // pack hello msg request to packet
    rfUint32 request_packet_size =
            rf627_protocol_old_pack_read_factory_params_msg_request_to_packet(
                (rfUint8*)TX, TX_SIZE, &read_factory_params_msg);

    //send_addr.sin_family = RF_AF_INET;
    dst_ip_addr = scanner->user_params.network.ip_address[0] << 24 |
                  scanner->user_params.network.ip_address[1] << 16 |
                  scanner->user_params.network.ip_address[2] << 8 |
                  scanner->user_params.network.ip_address[3];
    dst_port = scanner->user_params.network.service_port;



    if (rf627_protocol_send_packet_by_udp(
                scanner->m_svc_sock, TX, request_packet_size, dst_ip_addr, dst_port, 0, NULL))
    {
        scanner->msg_count++;
        const rfInt data_len =
                rf627_protocol_old_get_size_of_response_read_factory_params_packet();
        rfInt nret = network_platform.network_methods.recv_data(
                    scanner->m_svc_sock, RX, data_len);
        if (nret == data_len)
        {
            rfSize confirm_packet_size =
                    rf627_protocol_old_create_confirm_packet_from_response_packet(
                        TX, TX_SIZE, RX, RX_SIZE);
            if(confirm_packet_size > 0)
            {
                rf627_protocol_send_packet_by_udp(
                            scanner->m_svc_sock, TX, confirm_packet_size, dst_ip_addr, dst_port, 0, 0);
            }

            rf627_old_header_msg_t header =
                    rf627_protocol_old_unpack_header_msg_from_factory_params_packet(RX);

            if(header.serial_number == scanner->factory_params.general.serial)
            {
                rf627_old_factory_params_msg_t factory_msg =
                        rf627_protocol_old_unpack_payload_msg_from_factory_params_packet(RX);

                scanner->factory_params = *(rf627_old_factory_params_t*)&factory_msg;


                rfUint16 index = 0;
                parameter_t* p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_productCode");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 0;
                p->base.size = sizeof(scanner->factory_params.general.device_id);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.general.device_id;
                p->val_uint32->min = 0;
                p->val_uint32->max = 65535;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_serial");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 2;
                p->base.size = sizeof(scanner->factory_params.general.serial);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.general.serial;
                p->val_uint32->min = 0;
                p->val_uint32->max = 4294967295;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_pcbSerial");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 6;
                p->base.size = sizeof(scanner->factory_params.general.serial_of_pcb);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.general.serial_of_pcb;
                p->val_uint32->min = 0;
                p->val_uint32->max = 4294967295;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_lifeTime");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 10;
                p->base.size = sizeof(scanner->factory_params.general.operating_time_h);
                set_str(&p->base.units, "s");

                p->val_uint32->value =
                        scanner->factory_params.general.operating_time_h * 60 * 60 +
                        scanner->factory_params.general.operating_time_m * 60 +
                        scanner->factory_params.general.operating_time_s;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1577846272;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_workTime");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 16;
                p->base.size = sizeof(scanner->factory_params.general.runtime_h);
                set_str(&p->base.units, "s");

                p->val_uint32->value =
                        scanner->factory_params.general.runtime_h * 60 * 60 +
                        scanner->factory_params.general.runtime_m * 60 +
                        scanner->factory_params.general.runtime_s;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1577846272;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_startsCount");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 22;
                p->base.size = sizeof(scanner->factory_params.general.startup_counter);
                set_str(&p->base.units, "count");

                p->val_uint32->value = scanner->factory_params.general.startup_counter;
                p->val_uint32->min = 0;
                p->val_uint32->max = 8760;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_firmwareVer");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 26;
                p->base.size = sizeof(scanner->factory_params.general.firmware_ver);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.general.firmware_ver;
                p->val_uint32->min = 0;
                p->val_uint32->max = 4294967295;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_hardwareVer");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 30;
                p->base.size = sizeof(scanner->factory_params.general.hardware_ver);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.general.hardware_ver;
                p->val_uint32->min = 0;
                p->val_uint32->max = 4294967295;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_customerID");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 34;
                p->base.size = sizeof(scanner->factory_params.general.customer_id);
                set_str(&p->base.units, "id");

                p->val_uint32->value = scanner->factory_params.general.customer_id;
                p->val_uint32->min = 0;
                p->val_uint32->max = 4294967295;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_fpgaFreq");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 38;
                p->base.size = sizeof(scanner->factory_params.general.fpga_freq);
                set_str(&p->base.units, "Hz");

                p->val_uint32->value = scanner->factory_params.general.fpga_freq;
                p->val_uint32->min = 100000000;
                p->val_uint32->max = 100000000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_smr");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 42;
                p->base.size = sizeof(scanner->factory_params.general.base_z);
                set_str(&p->base.units, "mm");

                p->val_uint32->value = scanner->factory_params.general.base_z;
                p->val_uint32->min = 0;
                p->val_uint32->max = 10000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_mr");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 46;
                p->base.size = sizeof(scanner->factory_params.general.range_z);
                set_str(&p->base.units, "mm");

                p->val_uint32->value = scanner->factory_params.general.range_z;
                p->val_uint32->min = 0;
                p->val_uint32->max = 10000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_xsmr");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 50;
                p->base.size = sizeof(scanner->factory_params.general.range_x_start);
                set_str(&p->base.units, "mm");

                p->val_uint32->value = scanner->factory_params.general.range_x_start;
                p->val_uint32->min = 0;
                p->val_uint32->max = 10000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_xemr");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 54;
                p->base.size = sizeof(scanner->factory_params.general.range_x_end);
                set_str(&p->base.units, "mm");

                p->val_uint32->value = scanner->factory_params.general.range_x_end;
                p->val_uint32->min = 0;
                p->val_uint32->max = 20000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_pixDivider");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 58;
                p->base.size = sizeof(scanner->factory_params.general.pixels_divider);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.general.pixels_divider;
                p->val_uint32->min = 0;
                p->val_uint32->max = 65535;
                p->val_uint32->step = 8;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_profDivider");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 60;
                p->base.size = sizeof(scanner->factory_params.general.profiles_divider);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.general.profiles_divider;
                p->val_uint32->min = 0;
                p->val_uint32->max = 65535;
                p->val_uint32->step = 8;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_general_FsblRev");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 62;
                p->base.size = sizeof(scanner->factory_params.general.fsbl_version);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.general.fsbl_version;
                p->val_uint32->min = 0;
                p->val_uint32->max = 4294967295;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("string_t");
                set_str(&p->base.name,  "fact_general_oemDevName");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 66;
                p->base.size = rf_strlen(scanner->factory_params.general.oem_device_name) + 1;
                set_str(&p->base.units, "");

                p->val_str->value = memory_platform.rf_calloc(1, sizeof(rfChar) * p->base.size);
                memory_platform.rf_memcpy(
                            (void*)p->val_str->value,
                            scanner->factory_params.general.oem_device_name,
                            p->base.size);
                p->val_str->maxLen = sizeof (scanner->factory_params.general.oem_device_name);
                set_str(&p->val_str->defValue, "Laser scanner");
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("string_t");
                set_str(&p->base.name, "fact_sensor_name");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 158;
                p->base.size = rf_strlen(scanner->factory_params.sensor.name) + 1;
                set_str(&p->base.units, "");

                p->val_str->value = memory_platform.rf_calloc(1, sizeof(rfChar) * p->base.size);
                memory_platform.rf_memcpy(
                            (void*)p->val_str->value,
                            scanner->factory_params.sensor.name,
                            p->base.size);
                p->val_str->maxLen = sizeof (scanner->factory_params.sensor.name);
                set_str(&p->val_str->defValue, "TYPE1");
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_width");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 190;
                p->base.size = sizeof(scanner->factory_params.sensor.width);
                set_str(&p->base.units, "pixels");

                p->val_uint32->value = scanner->factory_params.sensor.width;
                p->val_uint32->min = 648;
                p->val_uint32->max = 648;
                p->val_uint32->step = 4;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_height");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 192;
                p->base.size = sizeof(scanner->factory_params.sensor.height);
                set_str(&p->base.units, "lines");

                p->val_uint32->value = scanner->factory_params.sensor.height;
                p->val_uint32->min = 488;
                p->val_uint32->max = 488;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_pixFreq");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 194;
                p->base.size = sizeof(scanner->factory_params.sensor.pixel_clock);
                set_str(&p->base.units, "Hz");

                p->val_uint32->value = scanner->factory_params.sensor.pixel_clock;
                p->val_uint32->min = 40000000;
                p->val_uint32->max = 40000000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_blackOdd");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 198;
                p->base.size = sizeof(scanner->factory_params.sensor.black_odd_lines);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.sensor.black_odd_lines;
                p->val_uint32->min = 0;
                p->val_uint32->max = 65535;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_blackEven");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 200;
                p->base.size = sizeof(scanner->factory_params.sensor.black_even_lines);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.sensor.black_even_lines;
                p->val_uint32->min = 0;
                p->val_uint32->max = 65535;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_frmConstPart");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 202;
                p->base.size = sizeof(scanner->factory_params.sensor.frame_cycle_const_part);
                set_str(&p->base.units, "ticks");

                p->val_uint32->value = scanner->factory_params.sensor.frame_cycle_const_part;
                p->val_uint32->min = 6500;
                p->val_uint32->max = 6500;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_frmPerLinePart");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 206;
                p->base.size = sizeof(scanner->factory_params.sensor.frame_cycle_per_line_part);
                set_str(&p->base.units, "ticks");

                p->val_uint32->value = scanner->factory_params.sensor.frame_cycle_per_line_part;
                p->val_uint32->min = 410;
                p->val_uint32->max = 410;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_FrameRate_or_Exposure");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 210;
                p->base.size = sizeof(scanner->factory_params.sensor.frame_rate_or_exposure);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.sensor.frame_rate_or_exposure;
                p->val_uint32->min = 0;
                p->val_uint32->max = 1;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kBoolEnum);
                rfInt* def = get_value_by_key_from_enum(p->val_uint32->enumValues, "false");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_minExposure");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 211;
                p->base.size = sizeof(scanner->factory_params.sensor.min_exposure);
                set_str(&p->base.units, "ns");

                p->val_uint32->value = scanner->factory_params.sensor.min_exposure;
                p->val_uint32->min = 0;
                p->val_uint32->max = 100000000;
                p->val_uint32->step = 10;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_imgFlip");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 215;
                p->base.size = sizeof(scanner->factory_params.sensor.image_flipping);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.sensor.image_flipping;
                p->val_uint32->min = 0;
                p->val_uint32->max = 3;
                p->val_uint32->step = 0;
                p->val_uint32->enumValues = createParamEnum(kFlipEnum);
                def = get_value_by_key_from_enum(p->val_uint32->enumValues, "No");
                if (def != NULL)
                    p->val_uint32->defValue = *def;
                else p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);



                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_sensor_maxExposure");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 216;
                p->base.size = sizeof(scanner->factory_params.sensor.max_exposure);
                set_str(&p->base.units, "ns");

                p->val_uint32->value = scanner->factory_params.sensor.max_exposure;
                p->val_uint32->min = 0;
                p->val_uint32->max = 300000000;
                p->val_uint32->step = 10;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);

                //edr_point1_value
                //edr_point2_value
                //edr_point1_pos
                //edr_point2_pos
                //init_regs


                p = create_parameter_from_type("u32_arr_t");
                set_str(&p->base.name, "fact_network_macAddr");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 595;
                p->base.size = sizeof (scanner->factory_params.network.mac);
                set_str(&p->base.units, "");

                p->arr_uint32->value = memory_platform.rf_calloc(1, sizeof(rfUint32) * 6);
                for (rfUint32 i = 0; i < p->base.size; i++)
                    p->arr_uint32->value[i] = scanner->factory_params.network.mac[i];
                p->arr_uint32->min = 0;
                p->arr_uint32->max = 255;
                p->arr_uint32->step = 0;
                p->arr_uint32->defCount = 6;
                p->arr_uint32->defValue = memory_platform.rf_calloc(1, sizeof (rfUint32) * 6);
                rfUint32 de_arr[6] = {0, 10, 53, 1, 2, 3};
                for (rfUint32 i = 0; i < 6; i++)
                    p->arr_uint32->defValue[i] = de_arr[i];
                p->arr_uint32->maxCount = 6;
                vector_add(scanner->params_list, p);




                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_eip_vendor_id");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 601;
                p->base.size = sizeof(scanner->factory_params.network.eip_vendor_id);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.network.eip_vendor_id;
                p->val_uint32->min = 0;
                p->val_uint32->max = 65535;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);




                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_eip_device_type");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 603;
                p->base.size = sizeof(scanner->factory_params.network.eip_device_type);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.network.eip_device_type;
                p->val_uint32->min = 0;
                p->val_uint32->max = 65535;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);




                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_network_forceAutoNegTime");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 605;
                p->base.size = sizeof(scanner->factory_params.network.force_autoneg_time);
                set_str(&p->base.units, "s");

                p->val_uint32->value = scanner->factory_params.network.force_autoneg_time;
                p->val_uint32->min = 0;
                p->val_uint32->max = 255;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);




                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_laser_waveLength");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 637;
                p->base.size = sizeof(scanner->factory_params.laser.wave_length);
                set_str(&p->base.units, "nm");

                p->val_uint32->value = scanner->factory_params.laser.wave_length;
                p->val_uint32->min = 0;
                p->val_uint32->max = 10000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);




                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_laser_koeff1");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 639;
                p->base.size = sizeof(scanner->factory_params.laser.koeff1);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.laser.koeff1;
                p->val_uint32->min = 0;
                p->val_uint32->max = 255;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);




                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_laser_koeff2");
                set_str(&p->base.access, "read_only");
                p->base.index = index++;
                p->base.offset = 640;
                p->base.size = sizeof(scanner->factory_params.laser.koeff2);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.laser.koeff2;
                p->val_uint32->min = 0;
                p->val_uint32->max = 255;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);




                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_laser_minValue");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 641;
                p->base.size = sizeof(scanner->factory_params.laser.min_value);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.laser.min_value;
                p->val_uint32->min = 0;
                p->val_uint32->max = 4095;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);




                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "fact_laser_maxValue");
                set_str(&p->base.access, "locked");
                p->base.index = index++;
                p->base.offset = 645;
                p->base.size = sizeof(scanner->factory_params.laser.max_value);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.laser.max_value;
                p->val_uint32->min = 0;
                p->val_uint32->max = 4095;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);

                //enable_mode_change


                //in1_min_delay
                //in1_max_delay
                //max_divider_in1
                //min_divider_in1

                //out1_min_delay
                //out1_max_delay
                //out1_min_pulse_width
                //out1_max_pulse_width
                //out2_min_delay
                //out2_max_delay
                //out2_min_pulse_width
                //out2_max_pulse_width


                p = create_parameter_from_type("uint32_t");
                set_str(&p->base.name, "user_dump_size");
                set_str(&p->base.access, "write");
                p->base.index = index++;
                p->base.offset = 809;
                p->base.size = sizeof(scanner->factory_params.profiles.max_dump_size);
                set_str(&p->base.units, "");

                p->val_uint32->value = scanner->factory_params.profiles.max_dump_size;
                p->val_uint32->min = 0;
                p->val_uint32->max = 80000;
                p->val_uint32->step = 0;
                p->val_uint32->defValue = p->val_uint32->value;
                vector_add(scanner->params_list, p);


                ret = TRUE;
            }


        }
    }
//    _mx[0].unlock();

    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);
    return ret;
}

#include <stdlib.h>

/**
 * @brief rf627_protocol_old_unpack_header_msg_from_profile_packet - unpack
 * payload msg from user_params network packet
 * @param buffer - ptr to network buffer
 * @return rf627_old_user_params_t
 */
rfUint32 rf627_protocol_old_pack_payload_msg_to_user_params_packet(
        rfUint8* buffer, vector_t *params_list)
{
    rfUint8 *buf = &buffer[0];



    for(rfSize i = 0; i < vector_count(params_list); i++)
    {
        parameter_t* p = vector_get(params_list, i);

        if (rf_strcmp("write", p->base.access) != 0)
            continue;

        if (p != NULL)
        {
            if(rf_strcmp("uint32_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], &p->val_uint32->value, p->base.size);
            }else if(rf_strcmp("uint64_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], &p->val_uint64->value, p->base.size);
            }else if(rf_strcmp("int32_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], &p->val_int32->value, p->base.size);
            }else if(rf_strcmp("int64_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], &p->val_int64->value, p->base.size);
            }else if(rf_strcmp("float_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], &p->val_flt->value, p->base.size);
            }else if(rf_strcmp("double_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], &p->val_dbl->value, p->base.size);
            }else if(rf_strcmp("u32_arr_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                {
                    rfUint32 size = 4;
                    if (p->arr_uint32->count != 0)
                        size = p->base.size / p->arr_uint32->count;
                    else if (p->arr_uint32->defCount != 0)
                        size = p->base.size / p->arr_uint32->defCount;

                    switch (size) {
                    case 1:
                    {
                        for(rfSize j = 0; j < p->arr_uint32->count; j++)
                        {
                            memory_platform.rf_memcpy(&buf[p->base.offset + j * 1],
                                    (rfUint8*)&p->arr_uint32->value[j], 1);
                        }
                        break;
                    }
                    case 2:
                    {
                        memory_platform.rf_memcpy(&buf[p->base.offset + i * 2],
                                (rfUint16*)&p->arr_uint32->value[i], 2);
                        break;
                    }
                    case 4:
                    {
                        memory_platform.rf_memcpy(&buf[p->base.offset + i * 4],
                                (rfUint32*)&p->arr_uint32->value[i], 4);
                        break;
                    }
                    default:
                        break;
                    }
                }

            }else if(rf_strcmp("u64_arr_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], p->arr_uint64->value,  p->base.size);
            }else if(rf_strcmp("i32_arr_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], p->arr_int32->value,  p->base.size);
            }else if(rf_strcmp("i64_arr_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], p->arr_int64->value,  p->base.size);
            }else if(rf_strcmp("flt_array_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], p->arr_flt->value,  p->base.size);
            }else if(rf_strcmp("dbl_array_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], p->arr_dbl->value,  p->base.size);
            }else if(rf_strcmp("string_t", p->base.type) == 0)
            {
                //if (rf_strcmp("write", p->base.access) == 0)
                    memory_platform.rf_memcpy(&buf[p->base.offset], p->val_str->value,  p->base.size);
            }
        }
    }

    return RF627_PROTOCOL_OLD_USER_REQUEST_PAYLOAD_PACKET_SIZE;
}

rfBool rf627_old_write_params_to_scanner(rf627_old_t* scanner)
{
    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);

    rfUint32 dst_ip_addr;
    rfUint16 dst_port;
    rfBool ret = 1;

    // create write_params msg request
    rf627_old_header_msg_t write_user_params_msg =
            rf627_protocol_old_create_write_user_params_msg_request(
                kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_ON,
                scanner->factory_params.general.serial,
                scanner->msg_count);

    // pack hello msg request to packet
    rfUint32 request_packet_size =
            rf627_protocol_old_pack_write_user_params_msg_request_to_packet(
                (rfUint8*)TX, TX_SIZE, &write_user_params_msg);

    //send_addr.sin_family = RF_AF_INET;
    dst_ip_addr = scanner->user_params.network.ip_address[0] << 24 |
                  scanner->user_params.network.ip_address[1] << 16 |
                  scanner->user_params.network.ip_address[2] << 8 |
                  scanner->user_params.network.ip_address[3];
    dst_port = scanner->user_params.network.service_port;


    rfUint8 payload[RF627_PROTOCOL_OLD_USER_REQUEST_PAYLOAD_PACKET_SIZE];
    memory_platform.rf_memset(payload, 0, RF627_PROTOCOL_OLD_USER_REQUEST_PAYLOAD_PACKET_SIZE);

    memory_platform.rf_memcpy(
            &payload[310],
            &scanner->user_params.sensor.gain_analog,
            sizeof(scanner->user_params.sensor.gain_analog));

    memory_platform.rf_memcpy(
            &payload[311],
            &scanner->user_params.sensor.gain_digital,
            sizeof(scanner->user_params.sensor.gain_digital));

    memory_platform.rf_memcpy(
            &payload[328],
            &scanner->user_params.sensor.exposure_hdr_mode,
            sizeof (scanner->user_params.sensor.exposure_hdr_mode));

    memory_platform.rf_memcpy(
            &payload[332],
            &scanner->user_params.sensor.column_exposure_max_div,
            sizeof (scanner->user_params.sensor.column_exposure_max_div));

    memory_platform.rf_memcpy(
            &payload[399],
            &scanner->user_params.roi.auto_position,
            sizeof (scanner->user_params.roi.auto_position));

    memory_platform.rf_memcpy(
            &payload[615],
            &scanner->user_params.image_processing.filter_width,
            sizeof (scanner->user_params.image_processing.filter_width));

    memory_platform.rf_memcpy(
            &payload[616],
            &scanner->user_params.image_processing.processing_mode,
            sizeof (scanner->user_params.image_processing.processing_mode));

    memory_platform.rf_memcpy(
            &payload[617],
            &scanner->user_params.image_processing.reduce_noise,
            sizeof (scanner->user_params.image_processing.reduce_noise));

    memory_platform.rf_memcpy(
            &payload[683],
            &scanner->user_params.laser.level_mode,
            sizeof (scanner->user_params.laser.level_mode));


    memory_platform.rf_memcpy(
            &payload[718],
            &scanner->user_params.inputs.preset_index,
            sizeof (scanner->user_params.inputs.preset_index));

    for (rfUint16 i = 0; i < 12; i++)
    {
        memory_platform.rf_memcpy(
                    &payload[719 + 26*i],
                &scanner->user_params.inputs.params[i].params_mask,
                sizeof (scanner->user_params.inputs.params[i].params_mask));

        memory_platform.rf_memcpy(
                    &payload[721 + 26*i],
                &scanner->user_params.inputs.params[i].in1_enable,
                sizeof (scanner->user_params.inputs.params[i].in1_enable));

        memory_platform.rf_memcpy(
                    &payload[722 + 26*i],
                &scanner->user_params.inputs.params[i].in1_mode,
                sizeof (scanner->user_params.inputs.params[i].in1_mode));

        memory_platform.rf_memcpy(
                    &payload[723 + 26*i],
                &scanner->user_params.inputs.params[i].in1_delay,
                sizeof (scanner->user_params.inputs.params[i].in1_delay));

        memory_platform.rf_memcpy(
                    &payload[727 + 26*i],
                &scanner->user_params.inputs.params[i].in1_decimation,
                sizeof (scanner->user_params.inputs.params[i].in1_decimation));

        memory_platform.rf_memcpy(
                    &payload[728 + 26*i],
                &scanner->user_params.inputs.params[i].in2_enable,
                sizeof (scanner->user_params.inputs.params[i].in2_enable));

        memory_platform.rf_memcpy(
                    &payload[729 + 26*i],
                &scanner->user_params.inputs.params[i].in2_mode,
                sizeof (scanner->user_params.inputs.params[i].in2_mode));

        memory_platform.rf_memcpy(
                    &payload[730 + 26*i],
                &scanner->user_params.inputs.params[i].in2_invert,
                sizeof (scanner->user_params.inputs.params[i].in2_invert));

        memory_platform.rf_memcpy(
                    &payload[731 + 26*i],
                &scanner->user_params.inputs.params[i].in3_enable,
                sizeof (scanner->user_params.inputs.params[i].in3_enable));

        memory_platform.rf_memcpy(
                    &payload[732 + 26*i],
                &scanner->user_params.inputs.params[i].in3_mode,
                sizeof (scanner->user_params.inputs.params[i].in3_mode));
    }


    memory_platform.rf_memcpy(
            &payload[1063],
            &scanner->user_params.outputs.out1_enable,
            sizeof(scanner->user_params.outputs.out1_enable));

    memory_platform.rf_memcpy(
            &payload[1064],
            &scanner->user_params.outputs.out1_mode,
            sizeof(scanner->user_params.outputs.out1_mode));

    memory_platform.rf_memcpy(
            &payload[1065],
            &scanner->user_params.outputs.out1_delay,
            sizeof(scanner->user_params.outputs.out1_delay));

    memory_platform.rf_memcpy(
            &payload[1069],
            &scanner->user_params.outputs.out1_pulse_width,
            sizeof(scanner->user_params.outputs.out1_pulse_width));

    memory_platform.rf_memcpy(
            &payload[1073],
            &scanner->user_params.outputs.out1_invert,
            sizeof(scanner->user_params.outputs.out1_invert));

    memory_platform.rf_memcpy(
            &payload[1074],
            &scanner->user_params.outputs.out2_enable,
            sizeof(scanner->user_params.outputs.out2_enable));

    memory_platform.rf_memcpy(
            &payload[1075],
            &scanner->user_params.outputs.out2_mode,
            sizeof(scanner->user_params.outputs.out2_mode));

    memory_platform.rf_memcpy(
            &payload[1076],
            &scanner->user_params.outputs.out2_delay,
            sizeof(scanner->user_params.outputs.out2_delay));

    memory_platform.rf_memcpy(
            &payload[1080],
            &scanner->user_params.outputs.out2_pulse_width,
            sizeof(scanner->user_params.outputs.out2_pulse_width));

    memory_platform.rf_memcpy(
            &payload[1084],
            &scanner->user_params.outputs.out2_invert,
            sizeof(scanner->user_params.outputs.out2_invert));

    rfUint32 payload_size = rf627_protocol_old_pack_payload_msg_to_user_params_packet(
                payload, scanner->params_list);

    if (rf627_protocol_send_packet_by_udp(
                scanner->m_svc_sock, TX, request_packet_size, dst_ip_addr, dst_port, payload_size, payload))
    {
        scanner->msg_count++;

        const rfInt data_len =
                rf627_protocol_old_get_size_of_response_write_user_params_packet();
        rfInt nret = network_platform.network_methods.recv_data(
                    scanner->m_svc_sock, RX, data_len);
        if (nret == data_len)
        {
            rfSize confirm_packet_size =
                    rf627_protocol_old_create_confirm_packet_from_response_packet(
                        TX, TX_SIZE, RX, RX_SIZE);
            if(confirm_packet_size > 0)
            {
                rf627_protocol_send_packet_by_udp(
                            scanner->m_svc_sock, TX, confirm_packet_size, dst_ip_addr, dst_port, 0, 0);
            }
        }
    }


    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);
    return ret;

}

rfBool rf627_old_save_params_to_scanner(rf627_old_t* scanner)
{
    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);

    rfUint32 dst_ip_addr;
    rfUint16 dst_port;
    rfBool ret = 1;

    // create write_params msg request
    rf627_old_header_msg_t write_user_params_msg =
            rf627_protocol_old_create_save_user_params_msg_request(
                kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_ON,
                scanner->factory_params.general.serial,
                scanner->msg_count);

    // pack hello msg request to packet
    rfUint32 request_packet_size =
            rf627_protocol_old_pack_save_user_params_msg_request_to_packet(
                (rfUint8*)TX, TX_SIZE, &write_user_params_msg);

    //send_addr.sin_family = RF_AF_INET;
    dst_ip_addr = scanner->user_params.network.ip_address[0] << 24 |
                  scanner->user_params.network.ip_address[1] << 16 |
                  scanner->user_params.network.ip_address[2] << 8 |
                  scanner->user_params.network.ip_address[3];
    dst_port = scanner->user_params.network.service_port;


    if (rf627_protocol_send_packet_by_udp(
                scanner->m_svc_sock, TX, request_packet_size, dst_ip_addr, dst_port, 0, NULL))
    {
        scanner->msg_count++;

        const rfInt data_len =
                rf627_protocol_old_get_size_of_response_save_user_params_packet();
        rfInt nret = network_platform.network_methods.recv_data(
                    scanner->m_svc_sock, RX, data_len);
        if (nret == data_len)
        {
            rfSize confirm_packet_size =
                    rf627_protocol_old_create_confirm_packet_from_response_packet(
                        TX, TX_SIZE, RX, RX_SIZE);
            if(confirm_packet_size > 0)
            {
                rf627_protocol_send_packet_by_udp(
                            scanner->m_svc_sock, TX, confirm_packet_size, dst_ip_addr, dst_port, 0, 0);
            }
        }
    }

    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);
    return ret;

}

parameter_t* rf627_old_get_parameter(
        rf627_old_t* scanner, const rfChar* param_name)
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

rfUint8 rf627_old_set_parameter(
        rf627_old_t* scanner, parameter_t* param)
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

rfUint8 rf627_old_set_parameter_by_name(
        rf627_old_t* scanner, const rfChar* param_name, rfUint32 count, va_list value)
{
    for(rfSize i = 0; i < vector_count(scanner->params_list); i++)
    {
        parameter_t* p = vector_get(scanner->params_list, i);
        if (rf_strcmp(p->base.name, param_name) == 0)
        {
            if (rf_strcmp(p->base.type, "string_t") == 0)
            {
                const rfChar* str_value = va_arg(value, const rfChar*);
                memory_platform.rf_memcpy(
                            (void*)p->val_str->value,
                            str_value,
                            rf_strlen(str_value));
                p->base.size = rf_strlen(str_value);
                return 0;
            }
            else if (rf_strcmp(p->base.type, "int32_t") == 0)
            {
                p->val_int32->value = va_arg(value, rfInt32);
                return 0;
            }
            else if (rf_strcmp(p->base.type, "int64_t") == 0)
            {
                p->val_int64->value = va_arg(value, rfInt64);
                return 0;
            }
            else if (rf_strcmp(p->base.type, "uint32_t") == 0)
            {
                p->val_uint32->value = va_arg(value, rfUint32);
                return 0;
            }
            else if (rf_strcmp(p->base.type, "uint64_t") == 0)
            {
                p->val_uint64->value = va_arg(value, rfUint64);
                return 0;
            }
            else if (rf_strcmp(p->base.type, "float_t") == 0)
            {
                p->val_flt->value = va_arg(value, rfDouble);
                return 0;
            }
            else if (rf_strcmp(p->base.type, "double_t") == 0)
            {
                p->val_dbl->value = va_arg(value, rfDouble);
                return 0;
            }
            else if (rf_strcmp(p->base.type, "u32_arr_t") == 0)
            {
                rfUint32 size = 4;
                if (p->arr_uint32->count != 0)
                    size = p->base.size / p->arr_uint32->count;
                else if (p->arr_uint32->defCount != 0)
                    size = p->base.size / p->arr_uint32->defCount;

                const rfUint32* str_value = va_arg(value, const rfUint32*);
                switch (size) {
                case 1:
                {
                    for(rfSize j = 0; j < count; j++)
                    {
                        p->arr_uint32->value[j] = (rfUint8)str_value[j];
                    }
                    p->base.size = count;
                    p->arr_uint32->count = count;
                    break;
                }
                case 2:
                {
                    for(rfSize j = 0; j < count; j++)
                    {
                        p->arr_uint32->value[j] = (rfUint16)str_value[j];
                    }
                    p->base.size = count * 2;
                    p->arr_uint32->count = count;
                    break;
                }
                case 4:
                {
                    for(rfSize j = 0; j < count; j++)
                    {
                        p->arr_uint32->value[j] = (rfUint32)str_value[j];
                    }
                    p->base.size = count * 4;
                    p->arr_uint32->count = count;
                    break;
                }
                default:
                    break;
                }

                return 0;
            }
        }
    }
    return 1;
}

rfUint8 rf627_old_command_set_counters(
        rf627_old_t* scanner, rfUint32 profile_counter, rfUint32 packet_counter)
{
    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);

    rfUint32 dst_ip_addr;
    rfUint16 dst_port;
    rfBool ret = 1;

    // create write_params msg request
    rf627_old_header_msg_t reset_counters_msg =
            rf627_protocol_old_create_command_set_counters_msg(
                kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_ON,
                scanner->factory_params.general.serial,
                scanner->msg_count,
                profile_counter,
                packet_counter);

    // pack hello msg request to packet
    rfUint32 command_packet_size =
            rf627_protocol_old_pack_write_user_params_msg_request_to_packet(
                (rfUint8*)TX, TX_SIZE, &reset_counters_msg);

    //send_addr.sin_family = RF_AF_INET;
    dst_ip_addr = scanner->user_params.network.ip_address[0] << 24 |
                  scanner->user_params.network.ip_address[1] << 16 |
                  scanner->user_params.network.ip_address[2] << 8 |
                  scanner->user_params.network.ip_address[3];
    dst_port = scanner->user_params.network.service_port;

    rfUint32 payload_size = 0;
    if(reset_counters_msg.payload_size != 0)
    {
        rfUint8 payload[RF627_PROTOCOL_OLD_COMMAND_SET_COUNTERS_PAYLOAD_PACKET_SIZE];

        payload_size =
                rf627_protocol_old_pack_payload_msg_to_command_set_counter_packet(
                    payload, profile_counter, packet_counter);

        if (rf627_protocol_send_packet_by_udp(
                    scanner->m_svc_sock, TX, command_packet_size, dst_ip_addr, dst_port, payload_size, payload))
        {
            scanner->msg_count++;

            const rfInt data_len =
                    rf627_protocol_old_get_size_of_response_write_user_params_packet();
            rfInt nret = network_platform.network_methods.recv_data(
                        scanner->m_svc_sock, RX, data_len);
            if (nret == data_len)
            {
                rfSize confirm_packet_size =
                        rf627_protocol_old_create_confirm_packet_from_response_packet(
                            TX, TX_SIZE, RX, RX_SIZE);
                if(confirm_packet_size > 0)
                {
                    rf627_protocol_send_packet_by_udp(
                                scanner->m_svc_sock, TX, confirm_packet_size, dst_ip_addr, dst_port, 0, 0);
                }
            }
        }
    }else if (rf627_protocol_send_packet_by_udp(
                scanner->m_svc_sock, TX, command_packet_size, dst_ip_addr, dst_port, payload_size, 0))
    {
        scanner->msg_count++;

        const rfInt data_len =
                rf627_protocol_old_get_size_of_response_write_user_params_packet();
        rfInt nret = network_platform.network_methods.recv_data(
                    scanner->m_svc_sock, RX, data_len);
        if (nret == data_len)
        {
            rfSize confirm_packet_size =
                    rf627_protocol_old_create_confirm_packet_from_response_packet(
                        TX, TX_SIZE, RX, RX_SIZE);
            if(confirm_packet_size > 0)
            {
                rf627_protocol_send_packet_by_udp(
                            scanner->m_svc_sock, TX, confirm_packet_size, dst_ip_addr, dst_port, 0, 0);
//                network_platform.network_methods.send_tcp_data(
//                            scanner->m_data_sock, TX, TX_SIZE);
            }
        }
    }

    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);
    return ret;

}

rfUint8 rf627_old_command_periphery_send(
        rf627_old_t* scanner,
        rfUint16 input_size, void* input_data,
        rfUint16* output_size, void** output_data)
{
    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);

    rfUint32 dst_ip_addr;
    rfUint16 dst_port;
    rfBool ret = 1;

    // create write_params msg request
    rf627_old_header_msg_t reset_counters_msg =
            rf627_protocol_old_create_command_periphery_send_msg(
                kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_ON,
                scanner->factory_params.general.serial,
                scanner->msg_count,
                input_size);

    // pack hello msg request to packet
    rfUint32 command_packet_size =
            rf627_protocol_old_pack_write_user_params_msg_request_to_packet(
                (rfUint8*)TX, TX_SIZE, &reset_counters_msg);

    //send_addr.sin_family = RF_AF_INET;
    dst_ip_addr = scanner->user_params.network.ip_address[0] << 24 |
                  scanner->user_params.network.ip_address[1] << 16 |
                  scanner->user_params.network.ip_address[2] << 8 |
                  scanner->user_params.network.ip_address[3];
    dst_port = scanner->user_params.network.service_port;

    rfUint32 payload_size = 0;
    if(reset_counters_msg.payload_size != 0)
    {
        rfUint8* payload = memory_platform.rf_calloc(input_size, sizeof (rfByte));

        payload_size =
                rf627_protocol_old_pack_payload_msg_to_command_periphery_send_packet(
                    payload, input_size, input_data);

        if (rf627_protocol_send_packet_by_udp(
                    scanner->m_svc_sock, TX, command_packet_size, dst_ip_addr, dst_port, payload_size, payload))
        {
            scanner->msg_count++;

            const rfInt data_len =
                    rf627_protocol_old_get_size_of_response_write_user_params_packet();
            rfInt nret = network_platform.network_methods.recv_data(
                        scanner->m_svc_sock, RX, data_len);
            if (nret == data_len)
            {
                rfSize confirm_packet_size =
                        rf627_protocol_old_create_confirm_packet_from_response_packet(
                            TX, TX_SIZE, RX, RX_SIZE);
                if(confirm_packet_size > 0)
                {
                    rf627_protocol_send_packet_by_udp(
                                scanner->m_svc_sock, TX, confirm_packet_size, dst_ip_addr, dst_port, 0, 0);
                }
            }else
            {
                *output_size = nret - 14;
                *output_data = memory_platform.rf_calloc(*output_size, sizeof (rfByte));
                memory_platform.rf_memcpy(*output_data, &RX[14], *output_size);
            }
        }

        memory_platform.rf_free(payload);
    }

    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);
    return ret;
}


rfBool rf627_old_reboot_device_request_to_scanner(rf627_old_t* scanner)
{
    rfSize RX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* RX = memory_platform.rf_calloc(1, RX_SIZE);
    rfSize TX_SIZE = rf627_protocol_old_get_size_of_header() + RF627_MAX_PAYLOAD_SIZE;
    rfUint8* TX =  memory_platform.rf_calloc(1, TX_SIZE);

    rfUint32 dst_ip_addr;
    rfUint16 dst_port;
    rfBool ret = 1;

    // create write_params msg request
    rf627_old_header_msg_t reboot_device_msg =
            rf627_protocol_old_create_reboot_msg_request(
                kRF627_OLD_PROTOCOL_HEADER_CONFIRMATION_OFF,
                scanner->factory_params.general.serial,
                scanner->msg_count);

    // pack hello msg request to packet
    rfUint32 request_packet_size =
            rf627_protocol_old_pack_reboot_msg_request_to_packet(
                (rfUint8*)TX, TX_SIZE, &reboot_device_msg);

    //send_addr.sin_family = RF_AF_INET;
    dst_ip_addr = scanner->user_params.network.ip_address[0] << 24 |
                  scanner->user_params.network.ip_address[1] << 16 |
                  scanner->user_params.network.ip_address[2] << 8 |
                  scanner->user_params.network.ip_address[3];
    dst_port = scanner->user_params.network.service_port;


    if (rf627_protocol_send_packet_by_udp(
                scanner->m_svc_sock, TX, request_packet_size, dst_ip_addr, dst_port, 0, NULL))
    {
        scanner->msg_count++;

        const rfInt data_len =
                rf627_protocol_old_get_size_of_response_save_user_params_packet();
        rfInt nret = network_platform.network_methods.recv_data(
                    scanner->m_svc_sock, RX, data_len);
        if (nret == data_len)
        {
            rfSize confirm_packet_size =
                    rf627_protocol_old_create_confirm_packet_from_response_packet(
                        TX, TX_SIZE, RX, RX_SIZE);
            if(confirm_packet_size > 0)
            {
                rf627_protocol_send_packet_by_udp(
                            scanner->m_svc_sock, TX, confirm_packet_size, dst_ip_addr, dst_port, 0, 0);
            }
        }
    }

    memory_platform.rf_free(RX);
    memory_platform.rf_free(TX);
    return ret;
}
