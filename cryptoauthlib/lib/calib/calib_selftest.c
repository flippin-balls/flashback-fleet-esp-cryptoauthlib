/**
 * \file
 * \brief CryptoAuthLib Basic API methods for SelfTest command.
 *
 * The SelfTest command performs a test of one or more of the cryptographic
 * engines within the device.
 *
 * \note List of devices that support this command - ATECC608A/B. Refer to
 *       device datasheet for full details.
 *
 * \copyright (c) 2015-2020 Microchip Technology Inc. and its subsidiaries.
 *
 * \page License
 *
 * Subject to your compliance with these terms, you may use Microchip software
 * and any derivatives exclusively with Microchip products. It is your
 * responsibility to comply with third party license terms applicable to your
 * use of third party software (including open source software) that may
 * accompany Microchip software.
 *
 * THIS SOFTWARE IS SUPPLIED BY MICROCHIP "AS IS". NO WARRANTIES, WHETHER
 * EXPRESS, IMPLIED OR STATUTORY, APPLY TO THIS SOFTWARE, INCLUDING ANY IMPLIED
 * WARRANTIES OF NON-INFRINGEMENT, MERCHANTABILITY, AND FITNESS FOR A
 * PARTICULAR PURPOSE. IN NO EVENT WILL MICROCHIP BE LIABLE FOR ANY INDIRECT,
 * SPECIAL, PUNITIVE, INCIDENTAL OR CONSEQUENTIAL LOSS, DAMAGE, COST OR EXPENSE
 * OF ANY KIND WHATSOEVER RELATED TO THE SOFTWARE, HOWEVER CAUSED, EVEN IF
 * MICROCHIP HAS BEEN ADVISED OF THE POSSIBILITY OR THE DAMAGES ARE
 * FORESEEABLE. TO THE FULLEST EXTENT ALLOWED BY LAW, MICROCHIP'S TOTAL
 * LIABILITY ON ALL CLAIMS IN ANY WAY RELATED TO THIS SOFTWARE WILL NOT EXCEED
 * THE AMOUNT OF FEES, IF ANY, THAT YOU HAVE PAID DIRECTLY TO MICROCHIP FOR
 * THIS SOFTWARE.
 */

#include "cryptoauthlib.h"

#if CALIB_SELFTEST_EN

#if (CA_MAX_PACKET_SIZE < ATCA_CMD_SIZE_MIN)
#error "Selftest command packet cannot be accommodated inside the maximum packet size provided"
#endif

/** \brief Executes the SelfTest command, which performs a test of one or more
 *          of the cryptographic engines within the ATECC608 chip.
 *
 *  \param[in]  device  Device context pointer
 *  \param[in]  mode    Functions to test. Can be a bit field combining any
 *                      of the following: SELFTEST_MODE_RNG,
 *                      SELFTEST_MODE_ECDSA_VERIFY, SELFTEST_MODE_ECDSA_SIGN,
 *                      SELFTEST_MODE_ECDH, SELFTEST_MODE_AES,
 *                      SELFTEST_MODE_SHA, SELFTEST_MODE_ALL.
 *  \param[in]  param2  Currently unused, should be 0.
 *  \param[out] result  Results are returned here as a bit field.
 *
 *  \return ATCA_SUCCESS on success, otherwise an error code.
 */
ATCA_STATUS calib_selftest(ATCADevice device, uint8_t mode, uint16_t param2, uint8_t* result)
{
    ATCAPacket * packet = NULL;
    ATCA_STATUS status;
    uint8_t response = 0;

    do
    {
        if (device == NULL)
        {
            status = ATCA_TRACE(ATCA_BAD_PARAM, "NULL pointer received");
            break;
        }

        packet = calib_packet_alloc();
        if(NULL == packet)
        {
            (void)ATCA_TRACE(ATCA_ALLOC_FAILURE, "calib_packet_alloc - failed");
            status = ATCA_ALLOC_FAILURE;
            break;
        }

        (void)memset(packet, 0x00, sizeof(ATCAPacket));

        // build a SelfTest command
        packet->param1 = mode;
        packet->param2 = param2;

        if ((status = atSelfTest(atcab_get_device_type_ext(device), packet)) != ATCA_SUCCESS)
        {
            (void)ATCA_TRACE(status, "atSelfTest - failed");
            break;
        }

        status = atca_execute_command(packet, device);

        /* CHECK THE TRANSACTION BEFORE INTERPRETING ITS BUFFER.
         *
         * The original code went straight to packet->data and only consulted `status` inside a
         * branch that could never be taken:
         *
         *     if ((response & (mode == 0u ? 1u : 0u)) != 0u)
         *
         * For any NON-ZERO mode -- which includes SELFTEST_MODE_RNG, the one this fleet uses --
         * the mask is 0, so `response & 0` is always 0 and the error branch is dead. Every
         * outcome fell through to the else, which returns ATCA_SUCCESS and reports the buffer as
         * a failure bitmap.
         *
         * So a transaction that never completed -- CRC error, short read, and now a deadline
         * timeout -- read back as "self-test ran, and here is its result", with a zeroed buffer
         * decoding as result=0, i.e. NOTHING FAILED. A chip that could not be reached reported
         * itself healthy. That sits directly on the RNG recovery path.
         *
         * Transport failures are now returned as themselves. Only a transaction that actually
         * completed gets its response decoded. */
        if (ATCA_SUCCESS != status)
        {
            calib_packet_free(packet);
            return status;
        }

        /* A SelfTest response is one byte; anything shorter is not a response we can read. */
        if (packet->data[ATCA_COUNT_IDX] < (ATCA_RSP_DATA_IDX + 1u))
        {
            calib_packet_free(packet);
            return ATCA_RX_FAIL;
        }

        response = packet->data[ATCA_RSP_DATA_IDX];

        /* The remaining ambiguity is real and is the chip's, not ours: for a completed command
         * some status bytes are indistinguishable from a failure bitmap. We keep the library's
         * original interpretation -- assume a self-test result -- but only now that the
         * transaction itself is known to have succeeded. */
        if (NULL != result)
        {
            *result = response;
        }

        calib_packet_free(packet);
        return ATCA_SUCCESS;
    } while (false);

    calib_packet_free(packet);
    return status;
}
#endif /* CALIB_SELFTEST_EN */
