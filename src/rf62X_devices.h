#ifndef RF62X_DEVICES_H
#define RF62X_DEVICES_H

#include "RF62Xtypes.h"
#include "RF62Xchannel.h"
#include "RF627protocol.h"

#include "rf62X_types.h"
#include "custom_vector.h"


//
// RF627
// old version (v1.x.x)
//

typedef struct
{
    config_options_t options;
    rf627_old_factory_params_t factory_params;
    rf627_old_user_params_t user_params;

    void* m_svc_sock;
    void* m_data_sock;
    rfUint16 msg_count;
    rfUint32 host_ip;

    vector_t *params_list;

    rf627_old_hello_info_by_service_protocol info_by_service_protocol;

}rf627_old_t;


/**
 * @brief rf627_old_search - Search for RF627-old devices over network
 * @param list - ptr to list of rf627-old objects. If not null list will be filled with found devices
 * @param ip_addr - the IP address of the adapter on which the connection should be established.
 * @return 0 on success
 */
uint8_t rf627_old_search_by_service_protocol(vector_t* list, rfUint32 ip_addr, rfUint32 timeout);


/**
 * @brief rf627_old_create_from_hello_msg
 * @param msg_info
 * @param init_msg_count
 * @return
 */
rf627_old_t* rf627_old_create_from_hello_msg(
        void* msg_info, rfUint16 init_msg_count);

/**
 * @brief get_hello_info_of_scanners - Get information about scanner from hello packet
 * @param device - prt to scanner
 * @param protocol - protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return 0 on success
 */
rf627_old_hello_info_by_service_protocol* rf627_old_get_info_about_scanner_by_service_protocol(rf627_old_t* scanner);

/**
 * @brief rf627_old_connect - Establish connection to the device
 * @param scanner - ptr to device
 * @return true on success
 */
rfBool rf627_old_connect(rf627_old_t* scanner);

/**
 * @brief rf627_old_disconnect - Close connection to the device
 * @param scanner - ptr to device
 */
void rf627_old_disconnect(rf627_old_t* scanner);

/**
 * @brief rf627_old_check_connection_by_service_protocol - check scanner
 * connection by service protocol
 *
 * @param scanner - ptr to device
 * @param timeout to check
 *
 * @return true if scanner connected
 */
rfBool rf627_old_check_connection_by_service_protocol(
        rf627_old_t* scanner, rfUint32 timeout);

/**
 * @brief rf627_old_free - free memory allocated for rf627-smart scanner type
 *
 * @param rf627_old_t - prt to scanner struct
 */
void rf627_old_free(rf627_old_t* scanner);

/**
 * @brief rf627_old_get_profile - Get measurement from scanner's data stream
 * @param scanner - ptr to device
 * @param zero_points - include zero points in return profile2D
 * @return ptr to rf627_old_profile_t structure
 */
rf627_old_profile2D_t* rf627_old_get_profile2D(rf627_old_t* scanner, rfBool zero_points);

/**
 * @brief rf627_old_get_profile - Get measurement from scanner's data stream
 * @param scanner - ptr to device
 * @param zero_points - include zero points in return profile2D
 * @return ptr to rf627_old_profile_t structure
 */
rf627_old_profile3D_t* rf627_old_get_profile3D(
        rf627_old_t* scanner, rfFloat step_size, rfFloat k,
        count_types_t count_type,
        rfBool zero_points,
        protocol_types_t protocol);

/**
 * @brief read_params_from_scanner - Read parameters from device to rfInternal structure.
 * This structure is accessible via get_params() function
 * @param scanner - ptr to scanner
 * @return 0 on success
 */
rfBool rf627_old_read_user_params_from_scanner(rf627_old_t* scanner);

/**
 * @brief read_params_from_scanner - Read parameters from device to rfInternal structure.
 * This structure is accessible via get_params() function
 * @param scanner - ptr to scanner
 * @return 0 on success
 */
rfBool rf627_old_read_factory_params_from_scanner(rf627_old_t* scanner);

/**
 * @brief rf627_old_write_params_to_scanner - Write current parameters to device.
 * @param scanner - ptr to scanner
 * @return 0 on success
 */
rfBool rf627_old_write_params_to_scanner(rf627_old_t* scanner);

/**
 * @brief rf627_old_save_params_to_scanner - Save current parameters to device.
 * @param scanner - ptr to scanner
 * @return 0 on success
 */
rfBool rf627_old_save_params_to_scanner(rf627_old_t* scanner);

/**
 * @brief rf627_old_get_parameter - Search parameters by his name
 * @param scanner - ptr to scanner
 * @param param_name - name of parameter
 * @return param on success, else - null
 */
parameter_t* rf627_old_get_parameter(
        rf627_old_t* scanner, const rfChar* param_name);

/**
 * @brief rf627_old_set_parameter - set parameters
 * @param scanner - ptr to scanner
 * @param param - ptr to parameter
 * @return 0 on success
 */
rfUint8 rf627_old_set_parameter(
        rf627_old_t* scanner, parameter_t* param);

/**
 * @brief rf627_old_set_parameter_by_name - set parameter by his name
 * @param scanner - ptr to scanner
 * @param param_name - param name
 * @param value - setting value
 * @return 0 on success
 */
rfUint8 rf627_old_set_parameter_by_name(
        rf627_old_t* scanner, const rfChar* param_name, rfUint32 count, va_list value);

/**
 * @brief rf627_old_command_set_counters
 * @param scanner
 * @param profile_counter
 * @param packet_counter
 * @return 0 on success
 */
rfUint8 rf627_old_command_set_counters(
        rf627_old_t* scanner, rfUint32 profile_counter, rfUint32 packet_counter);

/**
 * @brief rf627_old_command_set_counters
 * @param scanner
 * @param profile_counter
 * @param packet_counter
 * @return 0 on success
 */
rfUint8 rf627_old_command_periphery_send(
        rf627_old_t* scanner,
        rfUint16 input_size, void* input_data,
        rfUint16* output_size, void** output_data);

/**
 * @brief rf627_smart_reboot_device_request_to_scanner - command to restart device
 *
 * @param scanner - ptr to scanner
 *
 * @return true on success
 */
rfBool rf627_old_reboot_device_request_to_scanner(rf627_old_t* scanner);


//
// RF627
// Smart version (v2.x.x)
//

typedef struct
{
    RF62X_channel_t channel;
    void* m_data_sock;

    vector_t *params_list;

    rf627_smart_hello_info_by_service_protocol info_by_service_protocol;
    rf627_smart_calib_table_t calib_table;
    rf627_approx_table_t approx_table;
    rfBool is_connected;
    vector_t *protocol_settings_list;
    pthread_mutex_t protocol_settings_mutex;
}rf627_smart_t;

/**
 * @brief rf627_smart_search_by_service_protocol - Search for RF627-smart
 * devices over network
 *
 * @param list - ptr to list of rf627-smart objects. If not null list will be
 *        filled with found devices
 * @param ip_addr - the IP address of the adapter on which the connection
 *        should be established.
 *
 * @return number of detected scanners on success or error code
 */
rfUint8 rf627_smart_search_by_service_protocol(
        vector_t* list, rfUint32 ip_addr, rfUint32 timeout);

/**
 * @brief rf627_smart_search_by_service_protocol - Search for RF627-smart
 * devices over network
 *
 * @param list - ptr to list of rf627-smart objects. If not null list will be
 *        filled with found devices
 * @param ip_addr - the IP address of the adapter on which the connection
 *        should be established.
 *
 * @return number of detected scanners on success or error code
 */
rfUint8 rf627_smart_search_by_ip_by_service_protocol(
        vector_t* list, rfUint32 ip_host, rfChar* ip_src, rfUint32 timeout);


/**
 * @brief rf627_smart_get_scanner_info_by_service_protocol - Get info about
 * scanner received from service protocol
 *
 * @param scanner - ptr to scanner
 *
 * @return ptr to info struct on success, else - null
 */
rf627_smart_hello_info_by_service_protocol*
        rf627_smart_get_scanner_info_by_service_protocol(rf627_smart_t* scanner);


/**
 * @brief rf627_smart_free - free memory allocated for rf627-smart scanner type
 *
 * @param rf627_smart_t - prt to scanner struct
 */
void rf627_smart_free(rf627_smart_t* scanner);


/**
 * @brief rf627_smart_connect - Establish connection to the device
 *
 * @param scanner - ptr to device
 *
 * @return true on success
 */
rfBool rf627_smart_connect(rf627_smart_t* scanner);


/**
 * @brief rf627_smart_check_connection_by_service_protocol - check scanner
 * connection by service protocol
 *
 * @param scanner - ptr to device
 * @param timeout to check
 *
 * @return true if scanner connected
 */
rfBool rf627_smart_check_connection_by_service_protocol(
        rf627_smart_t* scanner, rfUint32 timeout);


/**
 * @brief rf627_smart_disconnect - Close connection to the device
 *
 * @param scanner - ptr to device
 *
 * @return true if scanner disconnected
 */
rfBool rf627_smart_disconnect(rf627_smart_t* scanner);


/**
 * @brief rf627_smart_get_profile2D - Get measurement from scanner's data stream
 *
 * @param scanner - ptr to device
 * @param zero_points - include zero points in return profile2D
 *
 * @return ptr to rf627_smart_profile2D_t structure on success, else - null
 */
rf627_smart_profile2D_t* rf627_smart_get_profile2D(
        rf627_smart_t* scanner, rfBool zero_points);

/**
 * @brief rf627_smart_send_profile2D_request_to_scanner - command to start measuring
 *
 * @param scanner - ptr to scanner
 * @param count of measurements
 *
 * @return true on success
 */
rfBool rf627_smart_send_profile2D_request_to_scanner(
        rf627_smart_t* scanner, rfUint32 count);

/**
 * @brief rf627_smart_reboot_device_request_to_scanner - command to restart device
 *
 * @param scanner - ptr to scanner
 *
 * @return true on success
 */
rfBool rf627_smart_reboot_device_request_to_scanner(rf627_smart_t* scanner);

/**
 * @brief rf627_smart_reboot_sensor_request_to_scanner - command to restart CMOS-sensor
 *
 * @param scanner - ptr to scanner
 *
 * @return true on success
 */
rfBool rf627_smart_reboot_sensor_request_to_scanner(rf627_smart_t* scanner);


/**
 * @brief rf627_smart_read_params_from_scanner - Read parameters from device to
 * SDK internal structure.
 * This structure is accessible via rf627_smart_get_parameter() function
 *
 * @param scanner - ptr to scanner
 * @param timeout to read
 *
 * @return true on success
 */
rfBool rf627_smart_read_params_from_scanner(
        rf627_smart_t* scanner, rfUint32 timeout);


/**
 * @brief rf627_smart_get_parameter - Get a parameter by its name
 *
 * @param scanner - ptr to scanner
 * @param param_name - name of parameter
 *
 * @return parameter on success, else - null
 */
parameter_t* rf627_smart_get_parameter(
        rf627_smart_t* scanner, const rfChar* param_name);


/**
 * @brief rf627_smart_set_parameter - set parameters in SDK internal structure.
 * This structure will have to be sent to the scanner via
 * rf627_smart_write_params_to_scanner() function
 *
 * @param scanner - ptr to scanner
 * @param param - ptr to parameter
 *
 * @return true on success
 */
rfUint8 rf627_smart_set_parameter(
        rf627_smart_t* scanner, parameter_t* param);


/**
 * @brief rf627_smart_write_params_to_scanner - Send internal SDK parameters to
 * the scanner for applying changes
 *
 * @param scanner - ptr to scanner
 * @param timeout to write
 *
 * @return true on success
 */
rfBool rf627_smart_write_params_to_scanner(
        rf627_smart_t* scanner, rfUint32 timeout);
/**
 * @brief rf627_smart_save_params_to_scanner - Save changes to device's memory
 *
 * @param scanner - ptr to scanner
 * @param timeout to save
 *
 * @return true on success
 */
rfBool rf627_smart_save_params_to_scanner(
        rf627_smart_t* scanner, rfUint32 timeout);

/**
 * @brief rf627_smart_save_recovery_params_to_scanner - Save current params in
 * the recovery area
 *
 * @param scanner - ptr to scanner
 * @param timeout to save
 *
 * @return true on success
 */
rfBool rf627_smart_save_recovery_params_to_scanner(
        rf627_smart_t* scanner, rfUint32 timeout);

/**
 * @brief rf627_smart_load_recovery_params_from_scanner - Loading device
 * parameters from the recovery area
 *
 * @param scanner - ptr to scanner
 * @param timeout to load
 *
 * @return true on success
 */
rfBool rf627_smart_load_recovery_params_from_scanner(
        rf627_smart_t* scanner, rfUint32 timeout);


/**
 * @brief rf627_smart_get_frame - Get frame from scanner
 *
 * @param scanner - ptr to scanner
 * @param confirm_enabled Enable confirmation
 * @param timeout to get
 *
 * @return ptr to rf627_smart_frame_t on success, else - null
 */
rf627_smart_frame_t* rf627_smart_get_frame(
        rf627_smart_t* scanner, rfBool confirm_enabled, rfUint32 timeout);


/**
 * @brief rf627_smart_get_dumps_profiles_by_service_protocol - Get
 * dumps profiles from scanner
 *
 * @param scanner - ptr to scanner
 * @param index Start number of the requested profile from memory
 * @param count The count of requested profiles
 * @param timeout to get
 * @param[out] profile_array Ptr to profile's array
 * @param[out] array_count Count of profiles in array
 * @param dump_unit_size Dump uint size per line
 * @return true on success
 */
rfBool rf627_smart_get_dumps_profiles_by_service_protocol(
        rf627_smart_t* scanner, uint32_t index, uint32_t count, rfUint32 timeout,
        rf627_profile2D_t** profile_array, uint32_t* array_count,
        uint32_t dump_unit_size);

/**
 * @brief rf627_smart_get_authorization_token_by_service_protocol - Get
 * authorization token from scanner
 *
 * @param scanner - ptr to scanner
 * @param token - addr to ptr char array for token string return
 * @param token_size - return token string size
 * @param timeout to get
 *
 * @return true on success
 */
rfBool rf627_smart_get_authorization_token_by_service_protocol(
        rf627_smart_t* scanner, char** token, rfUint32* token_size, rfUint32 timeout);


/**
 * @brief rf627_smart_set_authorization_key_by_service_protocol - Set
 * authorization key to scanner
 *
 * @param scanner - ptr to scanner
 * @param key - key char array
 * @param key_size - key char array size
 * @param timeout to set
 *
 * @return true on success
 */
rfBool rf627_smart_set_authorization_key_by_service_protocol(
        rf627_smart_t* scanner, char* key, rfUint32 key_size, rfUint32 timeout);


/**
 * @brief rf627_smart_create_calibration_table - Create calibration table
 * for scanner to SDK internal memory
 *
 * @param scanner - ptr to scanner
 * @param timeout to read
 *
 * @return true on success
 */
rfBool rf627_smart_create_calibration_table(
        rf627_smart_t* scanner, rfUint32 timeout);

/**
 * @brief rf627_smart_save_calibration_data_by_service_protocol - Get
 * calibration table from SDK internal memory
 *
 * @param scanner - ptr to scanner
 *
 * @return ptr to rf627_smart_calib_table_t on success, else - null
 */
rf627_smart_calib_table_t* rf627_smart_get_calibration_table(rf627_smart_t* scanner);


/**
 * @brief rf627_smart_save_calibration_data_by_service_protocol - Set
 * calibration table to SDK internal memory for sending to the scanner via
 * rf627_smart_write_calibration_data_by_service_protocol() function
 *
 * @param scanner - ptr to scanner
 * @param rf627_smart_calib_table_t - ptr to table
 *
 * @return true on success
 */
rfBool rf627_smart_set_calibration_table(
        rf627_smart_t* scanner, rf627_smart_calib_table_t* table);

/**
 * @brief rf627_smart_read_calibration_table_by_service_protocol - Read
 * calibration table from scanner to SDK internal memory
 *
 * @param scanner - ptr to scanner
 * @param timeout to read
 *
 * @return true on success
 */
rfBool rf627_smart_read_calibration_table_by_service_protocol(
        rf627_smart_t* scanner, rfUint32 timeout);


/**
 * @brief rf627_smart_write_calibration_data_by_service_protocol - Write
 * calibration table from SDK internal memory to scanner
 *
 * @param scanner - ptr to scanner
 * @param timeout to write
 *
 * @return true on success
 */
rfBool rf627_smart_write_calibration_table_by_service_protocol(
        rf627_smart_t* scanner, rfUint32 timeout);


/**
 * @brief rf627_smart_save_calibration_data_by_service_protocol - Save
 * calibration table in scanner memory
 *
 * @param scanner - ptr to scanner
 * @param timeout to save
 *
 * @return true on success
 */
rfBool rf627_smart_save_calibration_table_by_service_protocol(
        rf627_smart_t* scanner, rfUint32 timeout);


/**
 * @brief rf627_smart_create_approx_table - Create calibration table
 * for scanner to SDK internal memory
 *
 * @param scanner - ptr to scanner
 *
 * @return true on success
 */
rfBool rf627_smart_create_approx_table_v6(rf627_smart_t* scanner);

/**
 * @brief rf627_smart_save_calibration_data_by_service_protocol - Get
 * calibration table from SDK internal memory
 *
 * @param scanner - ptr to scanner
 *
 * @return ptr to rf627_smart_calib_table_t on success, else - null
 */
rf627_smart_approx_table_v6_t* rf627_smart_get_approx_table_v6(rf627_smart_t* scanner);


/**
 * @brief rf627_smart_save_calibration_data_by_service_protocol - Set
 * calibration table to SDK internal memory for sending to the scanner via
 * rf627_smart_write_calibration_data_by_service_protocol() function
 *
 * @param scanner - ptr to scanner
 * @param rf627_smart_calib_table_t - ptr to table
 *
 * @return true on success
 */
rfBool rf627_smart_set_approx_table_v6(
        rf627_smart_t* scanner, rf627_smart_approx_table_v6_t* table);

/**
 * @brief rf627_smart_read_calibration_table_by_service_protocol - Read
 * calibration table from scanner to SDK internal memory
 *
 * @param scanner - ptr to scanner
 * @param timeout to read
 *
 * @return true on success
 */
rfBool rf627_smart_read_approx_table_v6_by_service_protocol(
        rf627_smart_t* scanner, rfUint32 timeout);



/**
 * @brief rf627_smart_write_calibration_data_by_service_protocol - Write
 * calibration table from SDK internal memory to scanner
 *
 * @param scanner - ptr to scanner
 * @param timeout to write
 *
 * @return true on success
 */
rfBool rf627_smart_write_approx_table_v6_by_service_protocol(
        rf627_smart_t* scanner, rfUint32 timeout);


/**
 * @brief rf627_smart_save_calibration_data_by_service_protocol - Save
 * calibration table in scanner memory
 *
 * @param scanner - ptr to scanner
 * @param timeout to save
 *
 * @return true on success
 */
rfBool rf627_smart_save_approx_table_v6_by_service_protocol(
        rf627_smart_t* scanner, rfUint32 timeout);




/**
 * @brief rf627_smart_send_to_periphery_by_service_protocol - Send data
 * to periphery
 *
 * @param scanner Ptr to scanner
 * @param device_name Interface where the data will be sent. e.x. "usart0"
 * @param data Data to be sent
 * @param data_size Size of data
 * @param answ Answer to sent data
 * @param answ_size Answer data size
 * @param timeout to send and receive answer
 * @return true on success
 */
rfBool rf627_smart_send_to_periphery_by_service_protocol(
        rf627_smart_t* scanner, const rfChar* device_name, rfChar* data,
        rfUint32 data_size, char** answ, rfUint32* answ_size,  rfUint32 timeout);

/**
 * @brief rf627_smart_send_to_periphery_by_service_protocol - Send data
 * to periphery
 *
 * @param scanner Ptr to scanner
 * @param device_name Interface where the data will be sent. e.x. "usart0"
 * @param data Data to be sent
 * @param data_size Size of data
 * @param answ Answer to sent data
 * @param answ_size Answer data size
 * @param timeout to send and receive answer
 * @return true on success
 */
rfBool rf627_smart_receive_from_periphery_by_service_protocol(
        rf627_smart_t* scanner, const rfChar* device_name,
        rfUint16 count, char** answ, rfUint32* answ_size, rfUint32 timeout);

/**
 * @brief rf627_smart_send_custom_command - Send custom command.
 *
 * @param scanner Ptr to scanner
 * @param cmd_name Command name
 * @param data_type Data type to be sent
 * @param payload Data to be sent
 * @param payload_size Data size to be sent
 * @param out Data to be received
 * @param out_size Data size to be received
 *
 * @return true on success
 */
rfBool rf627_smart_send_custom_command(
        rf627_smart_t* scanner, const rfChar* cmd_name, const rfChar* data_type,
        rfChar* payload, uint32_t payload_size, rfChar** out, rfUint32* out_size);


/**
 * @brief rf627_smart_add_protocol_settings_for_cmd - Adding custom protocol
 * settings for a specific command
 *
 * @param scanner Ptr to scanner
 * @param cmd_name Command name
 * @param crc_enabled Enable checksum verification
 * @param confirm_enabled Enable confirmation
 * @param one_answ Wait for one response per request
 * @param waiting_time Time to wait for a response
 * @param resends_count Number of repetitions when a packet is lost
 *
 * @return true on success, else - false
 */
rfBool rf627_smart_add_protocol_settings_for_cmd(
        rf627_smart_t *scanner, const char *cmd_name,
        rfUint8 crc_enabled, rfUint8 confirm_enabled, rfUint8 one_answ,
        rfUint32 waiting_time, rfUint32 resends_count);

/**
 * @brief rf627_smart_remove_protocol_settings_for_cmd - Remove custom protocol
 * settings for a specific command
 *
 * @param scanner Ptr to scanner
 * @param cmd_name Command name
 *
 * @return true on success, else - false
 */
rfBool rf627_smart_remove_protocol_settings_for_cmd(
        rf627_smart_t *scanner, const char *cmd_name);


/**
 * @brief rf627_smart_send_to_periphery_by_service_protocol - Send data
 * to periphery
 *
 * @param scanner Ptr to scanner
 * @param device_name Interface where the data will be sent. e.x. "usart0"
 * @param data Data to be sent
 * @param data_size Size of data
 * @param answ Answer to sent data
 * @param answ_size Answer data size
 * @param timeout to send and receive answer
 * @return true on success
 */
rfBool rf627_smart_receive_firmware_by_service_protocol(
        rf627_smart_t* scanner, char** answ, rfUint32* answ_size, rfUint32 timeout);


typedef struct
{
    scanner_types_t type;
    union{
        rf627_old_t* rf627_old;
        rf627_smart_t* rf627_smart;
    };
}scanner_base_t;



#endif // RF62X_DEVICES_H
