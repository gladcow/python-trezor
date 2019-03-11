# This file is part of the Trezor project.
#
# Copyright (C) 2012-2018 SatoshiLabs and contributors
#
# This library is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License version 3
# as published by the Free Software Foundation.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the License along with this library.
# If not, see <https://www.gnu.org/licenses/lgpl-3.0.html>.

from trezorlib import btc, messages as proto
from trezorlib.tools import parse_path

from ..support.tx_cache import tx_cache
from .common import TrezorTest

TX_API = tx_cache("Dash")


class TestMsgSigntxDash(TrezorTest):
    def test_send_dash(self):
        self.setup_mnemonic_allallall()
        inp1 = proto.TxInputType(
            address_n=parse_path("44'/5'/0'/0/0"),
            # dash:XdTw4G5AWW4cogGd7ayybyBNDbuB45UpgH
            amount=1000000000,
            prev_hash=bytes.fromhex(
                "5579eaa64b2a0233e7d8d037f5a5afc957cedf48f1c4067e9e33ca6df22ab04f"
            ),
            prev_index=1,
            script_type=proto.InputScriptType.SPENDADDRESS,
        )
        out1 = proto.TxOutputType(
            address="XpTc36DPAeWmaueNBA9JqCg2GC8XDLKSYe",
            amount=999999000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        with self.client:
            self.client.set_expected_responses(
                [
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXMETA,
                        details=proto.TxRequestDetailsType(tx_hash=inp1.prev_hash),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.ConfirmOutput),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                self.client, "Dash", [inp1], [out1], prev_txes=TX_API
            )

        assert (
            serialized_tx.hex()
            == "01000000014fb02af26dca339e7e06c4f148dfce57c9afa5f537d0d8e733022a4ba6ea7955010000006a4730440220387be4d1e4b5e355614091416373e99e1a3532b8cc9a8629368060aff2681bdb02200a0c4a5e9eb2ce6adb6c2e01ec8f954463dcc04f531ed8a89a2b40019d5aeb0b012102936f80cac2ba719ddb238646eb6b78a170a55a52a9b9f08c43523a4a6bd5c896ffffffff0118c69a3b000000001976a9149710d6545407e78c326aa8c8ae386ec7f883b0af88ac00000000"
        )

    def test_send_dash_dip2_input(self):
        self.setup_mnemonic_allallall()
        inp1 = proto.TxInputType(
            address_n=parse_path("44'/5'/0'/0/0"),
            # dash:XdTw4G5AWW4cogGd7ayybyBNDbuB45UpgH
            amount=4095000260,
            prev_hash=bytes.fromhex(
                "15575a1c874bd60a819884e116c42e6791c8283ce1fc3b79f0d18531a61bbb8a"
            ),
            prev_index=1,
            script_type=proto.InputScriptType.SPENDADDRESS,
        )
        out1 = proto.TxOutputType(
            address_n=parse_path("44'/5'/0'/1/0"),
            amount=4000000000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        out2 = proto.TxOutputType(
            address="XrEFMNkxeipYHgEQKiJuqch8XzwrtfH5fm",
            amount=95000000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        with self.client:
            self.client.set_expected_responses(
                [
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXMETA,
                        details=proto.TxRequestDetailsType(tx_hash=inp1.prev_hash),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=39,
                            extra_data_offset=0,
                            tx_hash=inp1.prev_hash,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.ConfirmOutput),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                self.client, "Dash", [inp1], [out1, out2], prev_txes=TX_API
            )

        assert (
            serialized_tx.hex()
            == "01000000018abb1ba63185d1f0793bfce13c28c891672ec416e18498810ad64b871c5a5715010000006b483045022100f0442b6d9c7533cd6f74afa993b280ed9475276d69df4dac631bc3b5591ba71b022051daf125372c1c477681bbd804a6445d8ff6840901854fb0b485b1c6c7866c44012102936f80cac2ba719ddb238646eb6b78a170a55a52a9b9f08c43523a4a6bd5c896ffffffff0200286bee000000001976a914fd61dd017dad1f505c0511142cc9ac51ef3a5beb88acc095a905000000001976a914aa7a6a1f43dfc34d17e562ce1845b804b73fc31e88ac00000000"
        )

    def test_send_dash_dip2(self):
        self.setup_mnemonic_allallall()
        inp1 = proto.TxInputType(
            address_n=parse_path("44'/1'/0'/0/0"),
            # dash testnet:ybQPZRHKifv9BDqMN2cieCsMzQQ1BuDoR5
            amount=100710000000,
            prev_hash=bytes.fromhex(
                "696e01be235c7d08da1ac4cafeb186185b6e222a62de31ad6f1a80cb8ff3c58d"
            ),
            prev_index=1,
            script_type=proto.InputScriptType.SPENDADDRESS,
        )
        out1 = proto.TxOutputType(
            address_n=parse_path("44'/1'/0'/0/0/0/0"),
            amount=100000000000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        out2 = proto.TxOutputType(
            address_n=parse_path("44'/1'/0'/0/0"),
            amount=709999000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        extra_payload = bytes.fromhex(
                "d1010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c5a2d505da4f03b2776f588e4fee0118248dc044126d93a264c52fb494ed0eaa6ae71c2843fccf152e42b436193e16218256080339155421de6ecb19bede83b125ac0d50c5a2d505da4f03b2776f588e4fee0118248dc04400001976a914a579388225827d9f2fe9014add644487808c695d88acc3803e9de251fdfe2f6fa200638ae4675511ec0bf0180983ea7a0ab2acd7a50000"
            )
        with self.client:
            self.client.set_expected_responses(
                [
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXMETA,
                        details=proto.TxRequestDetailsType(tx_hash=inp1.prev_hash),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=0, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=1, tx_hash=inp1.prev_hash
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.ConfirmOutput),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXINPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=210,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=210,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                self.client, "Dash Testnet", [inp1], [out1, out2], prev_txes=TX_API, extra_payload=extra_payload
            )

        assert (
            serialized_tx.hex()
            == "03000100018dc5f38fcb801a6fad31de622a226e5b1886b1fecac41ada087d5c23be016e69010000006b483045022100f3ba5d64e79d68228de39f5ffd14d26324d5346f4808420fd90698267b598449022022bebdab8def40d07d4cce5df7d45420e656436bb3f48b95bbfc005ea40aabf10121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff0200e87648170000001976a9149e87e0cb3156d46468dde382b57964a9810991c088ac98b9512a000000001976a914a579388225827d9f2fe9014add644487808c695d88ac00000000d1010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c5a2d505da4f03b2776f588e4fee0118248dc044126d93a264c52fb494ed0eaa6ae71c2843fccf152e42b436193e16218256080339155421de6ecb19bede83b125ac0d50c5a2d505da4f03b2776f588e4fee0118248dc04400001976a914a579388225827d9f2fe9014add644487808c695d88acc3803e9de251fdfe2f6fa200638ae4675511ec0bf0180983ea7a0ab2acd7a50000"
        )

