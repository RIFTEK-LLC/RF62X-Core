/**
 * @file
 * @brief Header file with a description of the basic functions
 *
 * This file contains definitions of the main
 * functions used for development.
 */


#ifndef RF62X_SDK_H
#define RF62X_SDK_H

#include "platform_types.h"
#include "custom_vector.h"
#include "rf62X_devices.h"
#include "rf62X_types.h"

#define STREAM_SOCK_RECV_TIMEOUT 100

#if (defined _WIN32 && defined RF62X_LIBRARY)
    #define API_EXPORT __declspec(dllexport)
#else
    #define API_EXPORT
#endif


/**
 * @brief change_platform_adapter_settings - change adapter's settings
 *
 * @param[in] subnet_mask Subnet mask on your local machine. A subnet mask is a
 *            number that defines a range of IP addresses that can be used in a
 *            network.
 * @param[in] host_ip_addr IP address of your network adapter(card)
 */
API_EXPORT void set_platform_adapter_settings(
        rfUint32 subnet_mask, rfUint32 host_ip_addr);


/**
 * @brief search_scanners - Search for RF62X devices over network
 *
 * @param[out] list Ptr to list of rf627 objects. If not null list will be
 *                  filled with found devices
 * @param[in] type Scanner's type (RF627-old, RF627-smart)
 * @param[in] timeout Time to search
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 *
 * @return TRUE on success
 */
API_EXPORT rfUint8 search_scanners(
        vector_t *list, scanner_types_t type,
        rfUint32 timeout, protocol_types_t protocol);

API_EXPORT rfUint8 search_scanners_by_ip(
        vector_t *list, scanner_types_t type, rfChar* ip,
        rfUint32 timeout, protocol_types_t protocol);

/**
 * @brief get_info_about_scanner - Get information about scanner from
 * hello packet
 *
 * @param[in] device Ptr to scanner
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 *
 * @return hello_information on success
 */
API_EXPORT hello_information get_info_about_scanner(
        scanner_base_t *device, protocol_types_t protocol);

/**
 * @brief connect_to_scanner - Establish connection to the RF62X device
 *
 * @param[in] device Ptr to scanner
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 *
 * @return TRUE on success
 */
API_EXPORT rfUint8 connect_to_scanner(
        scanner_base_t *device, protocol_types_t protocol);

/**
 * @brief check_connection_to_scanner - Check connection to the RF62X device
 *
 * @param[in] device Ptr to scanner
 * @param[in] timeout Time to check connection
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 *
 * @return TRUE on success
 */
API_EXPORT rfUint8 check_connection_to_scanner(
        scanner_base_t *device, rfUint32 timeout, protocol_types_t protocol);


/**
 * @brief disconnect_from_scanner - Close connection to the device
 *
 * @param[in] device Prt to scanner
 * @param[in] protocol Protocol's type (Service, ENIP, Modbus-TCP)
 *
 * @return TRUE on success
 */
API_EXPORT rfUint8 disconnect_from_scanner(
        scanner_base_t *device, protocol_types_t protocol);


/**
 * @brief free_scanner - Cleanup resources allocated by device
 *
 * @param[in] device Prt to scanner
 */
API_EXPORT void free_scanner(scanner_base_t *device);

/**
 * @brief get_profile2D_from_scanner - Get measurement from scanner's
 * data stream
 *
 * @param[in] device - ptr to scanner
 * @param[in] zero_points Enable zero points in return profile2D
 * @param[in] realtime Enable getting profile in real time (buffering disabled)
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 *
 * @return ptr to rf627_profile_t structure
 */
API_EXPORT rf627_profile2D_t* get_profile2D_from_scanner(
        scanner_base_t *device, rfBool zero_points,
        rfBool realtime, protocol_types_t protocol);

/**
 * @brief send_profile2D_request_to_scanner - Command to start profiles
 * measuring.
 * @param[in] device Ptr to scanner
 * @param[in] count The count of measurements
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT uint8_t send_profile2D_request_to_scanner(
        scanner_base_t *device, rfUint32 count, protocol_types_t protocol);

/**
 * @brief free_profile2D - Cleanup resources allocated for profile2D
 *
 * @param[in] profile Ptr to rf627_profile2D_t
 */
API_EXPORT void free_profile2D(rf627_profile2D_t* profile);


/** TODO
 * @brief get_profile3D_from_scanner -
 * @param device
 * @param step_size
 * @param k
 * @param count_type
 * @param zero_points
 * @param protocol
 * @return
 */
API_EXPORT rf627_profile3D_t* get_profile3D_from_scanner(
        scanner_base_t *device, rfFloat step_size, rfFloat k,
        count_types_t count_type,
        rfBool zero_points,
        protocol_types_t protocol);

/**
 * @brief get_frame_from_scanner - Get RAW frame from scanner
 * @param[in] device Ptr to scanner
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return ptr to rf627_frame_t structure
 */
API_EXPORT rf627_frame_t* get_frame_from_scanner(
        scanner_base_t *device, protocol_types_t protocol);

/**
 * @brief read_params_from_scanner - Read parameters from device to rfInternal
 * structure.
 *
 * @param device Ptr to scanner
 * @param timeout Time to read parameters
 * @param protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 *
 * @return TRUE on success
 */
API_EXPORT rfUint8 read_params_from_scanner(
        scanner_base_t *device, rfUint32 timeout, protocol_types_t protocol);

/**
 * @brief write_params_to_scanner - Send current parameters to device
 *
 * @param device Ptr to scanner
 * @param timeout Time to send parameters
 * @param protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 *
 * @return TRUE on success
 */
API_EXPORT rfUint8 write_params_to_scanner(
        scanner_base_t *device, rfUint32 timeout, protocol_types_t protocol);
/**
 * @brief save_params_to_scanner - Save changes to device's memory
 *
 * @param device Ptr to scanner
 * @param timeout Time to save parameters
 * @param protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 *
 * @return TRUE on success
 */
API_EXPORT rfUint8 save_params_to_scanner(
        scanner_base_t *device, rfUint32 timeout, protocol_types_t protocol);

/**
 * @brief load_recovery_params_from_scanner - Loading parameters from recovery
 * @param device - ptr to scanner
 * @param protocol - protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT rfUint8 load_recovery_params_from_scanner(
        scanner_base_t *device, uint32_t timeout, protocol_types_t protocol);

/**
 * @brief get_parameter - Search parameters by his name
 *
 * @param device - ptr to scanner
 * @param param_name - name of parameter
 *
 * @return param on success, else - null
 */
API_EXPORT parameter_t* get_parameter(
        scanner_base_t *device, const rfChar* param_name);

/**
 * @brief set_parameter - Set parameter
 *
 * @param device Ptr to scanner
 * @param param Parameter name
 *
 * @return TRUE on success
 */
API_EXPORT rfUint8 set_parameter(
        scanner_base_t *device, parameter_t* param);

parameter_t* create_parameter_from_type(const rfChar* type);

/**
 * @brief free_parameter - free parameter
 *
 * @param param: ptr to parameter
 * @param type: scaner type
 */
API_EXPORT void free_parameter(parameter_t* param, scanner_types_t type);

/**
 * @brief set_parameter_by_name - Set parameters by his name
 *
 * @param device - ptr to scanner
 * @param param_name - parameter name
 * @param value - value
 *
 * @return TRUE on success
 */
API_EXPORT rfUint8 set_parameter_by_name(
        scanner_base_t *device, const char* param_name,
        rfUint32 count, va_list value);

/**
 * @brief get_dumps_profiles_from_scanner - getting the content of the
 * profile dump
 * @param[in] device Ptr to scanner
 * @param[in] index Start number of the requested profile from memory
 * @param[in] count The count of requested profiles
 * @param[in] timeout Time to receive dump
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @param[out] dump Ptr to array from ptr to rf627_profile2D_t structures
 * @param[out] dump_size Size of returned Array from ptrs to rf627_profile2D_t
 * @param[in] dump_unit_size Size of cell for storing profile in the dump
 * @return TRUE on success
 */
API_EXPORT rfUint8 get_dumps_profiles_from_scanner(
        scanner_base_t *device, uint32_t index, uint32_t count,
        uint32_t timeout, protocol_types_t protocol,
        rf627_profile2D_t** dump, uint32_t* dump_size, uint32_t dump_unit_size);

/**
 * @brief get_authorization_token_from_scanner - Get authorization token
 * from scanner
 * @param[in] device Ptr to scanner
 * @param[out] token Returned authorization token.
 * @param[out] token_size Size of returned authorization token
 * @param[in] timeout Time to receive token
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT rfUint8 get_authorization_token_from_scanner(
        scanner_base_t *device, char** token, uint32_t* token_size,
        uint32_t timeout, protocol_types_t protocol);

/**
 * @brief set_authorization_key_to_scanner - Set authorization key to scanner
 * @param[in] device Ptr to scanner
 * @param[in] key Authorization key.
 * @param[in] key_size Size of authorization key.
 * @param[in] timeout Time to receive token
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT rfUint8 set_authorization_key_to_scanner(
        scanner_base_t *device, char* key, uint32_t key_size,
        uint32_t timeout, protocol_types_t protocol);


/**
 * @brief create_calibration_table_for_scanner - Create calibration table
 * for scanner
 * @param[in] device Ptr to scanner
 * @param[in] timeout Time to receive token
 * @return TRUE on success
 */
API_EXPORT rfUint8 create_calibration_table_for_scanner(
        scanner_base_t *device, uint32_t timeout);

/**
 * @brief read_calibration_table_from_scanner - Read calibration table
 * from scanner
 * @param[in] device Ptr to scanner
 * @param[in] timeout Time to receive token
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT rfUint8 read_calibration_table_from_scanner(
        scanner_base_t *device, uint32_t timeout, protocol_types_t protocol);

/**
 * @brief convert_calibration_table_from_bytes - Convert Calibration Table
 * from bytes
 * @param[in] bytes Ptr to byte array
 * @param[in] data_size Size of byte array
 * @return Ptr to rf627_calib_table_t
 */
API_EXPORT rf627_calib_table_t* convert_calibration_table_from_bytes(
        char* bytes, uint32_t data_size);

/**
 * @brief convert_calibration_table_to_bytes - Convert Calibration Table
 * to bytes
 * @param[in] table Ptr to rf627_calib_table_t
 * @param[out] bytes Returned byte array
 * @param[out] data_size Size of returned byte array
 * @return TRUE on success
 */
API_EXPORT rfBool convert_calibration_table_to_bytes(
        rf627_calib_table_t* table, char** bytes, uint32_t* data_size);

/**
 * @brief write_calibration_table_to_scanner - Write calibration table
 * to scanner
 * @param[in] device Ptr to scanner
 * @param[in] timeout Time to receive token
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT rfUint8 write_calibration_table_to_scanner(
        scanner_base_t *device, uint32_t timeout, protocol_types_t protocol);

/**
 * @brief get_calibration_table_from_scanner - Get calibration table from
 * internal SDK memory
 * @param[in] device Ptr to scanner
 * @param[in] timeout Time to receive token
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return Ptr to rf627_calib_table_t
 */
API_EXPORT rf627_calib_table_t* get_calibration_table_from_scanner(
        scanner_base_t *device, uint32_t timeout, protocol_types_t protocol);

/**
 * @brief set_calibration_table_to_scanner - Set calibration table to internal
 * SDK memory
 * @param[in] device Ptr to scanner
 * @param[in] table Ptr to rf627_calib_table_t
 * @param[in] timeout Time to receive token
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT rfUint8 set_calibration_table_to_scanner(
        scanner_base_t *device, rf627_calib_table_t* table,
        uint32_t timeout, protocol_types_t protocol);

/**
 * @brief save_calibration_table_to_scanner - Save calibration table
 * to device's memory
 * @param[in] device Ptr to scanner
 * @param[in] timeout Time to receive token
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT rfUint8 save_calibration_table_to_scanner(
        scanner_base_t *device, uint32_t timeout, protocol_types_t protocol);

/**
 * @brief send_reboot_device_request_to_scanner - The scanner will restart
 * @param[in] device Ptr to scanner
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT uint8_t send_reboot_device_request_to_scanner(
        scanner_base_t *device, protocol_types_t protocol);

/**
 * @brief send_reboot_sensor_request_to_scanner - The CMOS-sensor will restart
 * @param[in] device Ptr to scanner
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT uint8_t send_reboot_sensor_request_to_scanner(
        scanner_base_t *device, protocol_types_t protocol);

/**
 * @brief send_data_to_scanner_periphery - The CMOS-sensor will restart
 * @param[in] device Ptr to scanner
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT uint8_t send_data_to_scanner_periphery(
        scanner_base_t *device, const rfChar* iface_name, rfUint32 timeout,
        rfChar* in, rfUint32 in_size, rfChar** out, rfUint32* out_size);

/**
 * @brief receive_data_from_scanner_periphery - The CMOS-sensor will restart
 * @param[in] device Ptr to scanner
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT uint8_t receive_data_from_scanner_periphery(
        scanner_base_t *device, const rfChar* iface_name, rfUint32 timeout,
        rfUint16 count, rfChar** out, rfUint32* out_size);

/**
 * @brief receive_data_from_scanner_periphery - The CMOS-sensor will restart
 * @param[in] device Ptr to scanner
 * @param[in] protocol Protocol's type (Service Protocol, ENIP, Modbus-TCP)
 * @return TRUE on success
 */
API_EXPORT uint8_t receive_firmware_from_scanner(
        scanner_base_t *device, rfUint32 timeout, rfChar** out, rfUint32* out_size);



/**
 * @brief add_protocol_settings_for_cmd - Adding custom protocol settings for a
 * specific command
 *
 * @param device Ptr to scanner
 * @param cmd_name Command name
 * @param crc_enabled Enable checksum verification
 * @param confirm_enabled Enable confirmation
 * @param one_answ Wait for one response per request
 * @param waiting_time Time to wait for a response
 * @param resends_count Number of repetitions when a packet is lost
 *
 * @return true on success, else - false
 */
API_EXPORT uint8_t add_protocol_settings_for_cmd(
        scanner_base_t *device, const char* cmd_name, rfUint8 crc_enabled,
        rfUint8 confirm_enabled, rfUint8 one_answ, rfUint32 waiting_time, rfUint32 resends_count);

/**
 * @brief send_custom_command_to_scanner - Send custom command to device.
 * @details Use the add_protocol_settings_for_cmd method to add specific before
 *
 * @param device Ptr to scanner
 * @param cmd_name Command name
 * @param data_type Data type
 * @param in Data to be sent.
 * @param in_size Data size to be sent
 * @param out Data to be received
 * @param out_size Data size to be received.
 *
 * @return true on seccess, else false.
 */
API_EXPORT uint8_t send_custom_command_to_scanner(
        scanner_base_t *device, const rfChar* cmd_name, const rfChar* data_type,
        rfChar* in, rfUint32 in_size, rfChar** out, rfUint32* out_size);

/**
 * @brief remove_protocol_settings_for_cmd - Clear custom protocol settings for a
 * specific command.
 *
 * @param device Ptr to scanner
 * @param cmd_name Command name
 *
 * @return true on success, else - false
 */
API_EXPORT uint8_t remove_protocol_settings_for_cmd(
        scanner_base_t *device, const char* cmd_name);

/** TODO
 * @brief set_parameter - Search parameters by his name
 * @param device - ptr to scanner
 * @param param_name - name of parameter
 * @return param on success, else - null
 */
API_EXPORT rfUint8 send_command(
        scanner_base_t *device, command_t* command);

/** TODO
 * @brief set_parameter - Search parameters by his name
 * @param device - ptr to scanner
 * @param param_name - name of parameter
 * @return param on success, else - null
 */
API_EXPORT rfUint8 send_command2(
        scanner_base_t *device, command2_t* command);

#endif // RF62X_SDK_H
