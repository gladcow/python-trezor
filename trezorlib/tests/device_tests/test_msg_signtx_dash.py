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

    def test_send_dash_dip2_proregtx(self):
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
            address_n=parse_path("44'/1'/0'/0/0/0"),
            amount=100000000000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        out2 = proto.TxOutputType(
            address_n=parse_path("44'/1'/0'/0/0"),
            amount=709999000,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        extra_payload = bytes.fromhex(
                "d1010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c5a2d505da4f03b2776f588e4fee0118248dc044126d93a264c52fb494ed0eaa6ae71c2843fccf152e42b436193e16218256080339155421de6ecb19bede83b125ac0d50c5a2d505da4f03b2776f588e4fee0118248dc04400001976a914a579388225827d9f2fe9014add644487808c695d88ac00a5d7acb20a7aea830918f00bec115567e48a6300a26f2ffefd51e29d3e80c300"
            )
        txdata = proto.SignTx()
        txdata.version = (1 << 16) | 3
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
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=1),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=202,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
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
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=202,
                            extra_data_offset=8,
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
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=202,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                self.client, "Dash Testnet", [inp1], [out1, out2], details=txdata, prev_txes=TX_API, extra_payload=extra_payload
            )
        assert (
            serialized_tx.hex()
            == "03000100018dc5f38fcb801a6fad31de622a226e5b1886b1fecac41ada087d5c23be016e69010000006a473044022038e36c984245923623774346e754581e2042672fc464ae85b404ea45c271d65e0220084aedc68be95ad2d3918ba933e7ea9038056beeae280a2d42fa445b8bdf2ac90121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff0200e87648170000001976a9149e87e0cb3156d46468dde382b57964a9810991c088ac98b9512a000000001976a914a579388225827d9f2fe9014add644487808c695d88ac00000000d1010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c5a2d505da4f03b2776f588e4fee0118248dc044126d93a264c52fb494ed0eaa6ae71c2843fccf152e42b436193e16218256080339155421de6ecb19bede83b125ac0d50c5a2d505da4f03b2776f588e4fee0118248dc04400001976a914a579388225827d9f2fe9014add644487808c695d88ac00a5d7acb20a7aea830918f00bec115567e48a6300a26f2ffefd51e29d3e80c300"
        )

    def test_send_dash_dip2_proregtx_external(self):
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
            address_n=parse_path("44'/1'/0'/0/0"),
            amount=100709999750,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        extra_payload = bytes.fromhex(
                "fd12010100000000009b9054ff7839b940277b8eb8211570b2f16850ef729ee635e24d722fbc4a46230100000000000000000000000000ffffc6c74af14e1fc5a2d505da4f03b2776f588e4fee0118248dc044972f4481e23ea3b34a974349c44d8b96974ffb1e83cecb879564dcaa8b3ef58d84866dd672ad3d2db73904a9fa5c3b06c5a2d505da4f03b2776f588e4fee0118248dc0440b091976a914a579388225827d9f2fe9014add644487808c695d88ac00a5d7acb20a7aea830918f00bec115567e48a6300a26f2ffefd51e29d3e80c3411f43ef123ad4d5b1aff6c3834f6fc7589ce550e30d4d01e9e550fe39744f78753711e328b10282f04ff32853cb85d40694d6190c2de23d900be487847c5fb9b8be"
            )
        collateral_id = bytes.fromhex("23464abc2f724de235e69e72ef5068f1b2701521b88e7b2740b93978ff54909b")
        collateral_out = 1
        txdata = proto.SignTx()
        txdata.version = (1 << 16) | 3
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
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=269,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(
                            request_index=collateral_out,
                            tx_hash=collateral_id,
                        ),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
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
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=269,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=269,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                self.client, "Dash Testnet", [inp1], [out1], details=txdata,
                prev_txes=TX_API, extra_payload=extra_payload,
                external_txes=[collateral_id]
            )
        assert (
            serialized_tx.hex()
            == "03000100018dc5f38fcb801a6fad31de622a226e5b1886b1fecac41ada087d5c23be016e69010000006b4830450221008fe8324ab3322dbe1c5272b6fea297c648bef75685b485fe6edcb3ebacd0376802202b63d5646d0180ff5597f559546b25e1c7d13709625ed5601099bb6f1e313aac0121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff0186a4c872170000001976a914a579388225827d9f2fe9014add644487808c695d88ac00000000fd12010100000000009b9054ff7839b940277b8eb8211570b2f16850ef729ee635e24d722fbc4a46230100000000000000000000000000ffffc6c74af14e1fc5a2d505da4f03b2776f588e4fee0118248dc044972f4481e23ea3b34a974349c44d8b96974ffb1e83cecb879564dcaa8b3ef58d84866dd672ad3d2db73904a9fa5c3b06c5a2d505da4f03b2776f588e4fee0118248dc0440b091976a914a579388225827d9f2fe9014add644487808c695d88ac00a5d7acb20a7aea830918f00bec115567e48a6300a26f2ffefd51e29d3e80c3411f43ef123ad4d5b1aff6c3834f6fc7589ce550e30d4d01e9e550fe39744f78753711e328b10282f04ff32853cb85d40694d6190c2de23d900be487847c5fb9b8be"
        )

    def test_send_dash_dip2_proupservtx(self):
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
            address_n=parse_path("44'/1'/0'/0/0"),
            amount=100709999750,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        extra_payload = bytes.fromhex(
                "b5010061d48e8bd82f0fe9dba3413753c90b695ae75dccee5b3401e76df29b9d33a13900000000000000000000ffffc6c74af14e1f0000a5d7acb20a7aea830918f00bec115567e48a6300a26f2ffefd51e29d3e80c31612dc4544fc470415cdd4be5659fee6aa7d84c3572c712f5904b2e5d38cb217762717d88e4e1a956a9e82ce132e2b9b144e26cb3ff1e53675ede2769d99f46796ea0b8cbf33b78c15fe9a437dc4d1131ce2af8fd2ed5b306b326f9fcffcd416"
            )
        txdata = proto.SignTx()
        txdata.version = (2 << 16) | 3
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
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=174,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
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
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=174,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=174,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                self.client, "Dash Testnet", [inp1], [out1], details=txdata, prev_txes=TX_API, extra_payload=extra_payload
            )
        assert (
            serialized_tx.hex()
            == "03000200018dc5f38fcb801a6fad31de622a226e5b1886b1fecac41ada087d5c23be016e69010000006b483045022100fb07a91aa09f4df4da9573f472b79ae5966e800d3bcc762993eb0ec10396b9d902206574b0c26c7cdf31efbf25aaa5804c69c6b62cc912fe6990f3a1881ccc08965a0121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff0186a4c872170000001976a914a579388225827d9f2fe9014add644487808c695d88ac00000000b5010061d48e8bd82f0fe9dba3413753c90b695ae75dccee5b3401e76df29b9d33a13900000000000000000000ffffc6c74af14e1f0000a5d7acb20a7aea830918f00bec115567e48a6300a26f2ffefd51e29d3e80c31612dc4544fc470415cdd4be5659fee6aa7d84c3572c712f5904b2e5d38cb217762717d88e4e1a956a9e82ce132e2b9b144e26cb3ff1e53675ede2769d99f46796ea0b8cbf33b78c15fe9a437dc4d1131ce2af8fd2ed5b306b326f9fcffcd416"
        )

    def test_send_dash_dip2_proupregtx(self):
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
            address_n=parse_path("44'/1'/0'/0/0"),
            amount=100709999750,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        extra_payload = bytes.fromhex(
                "e4010061d48e8bd82f0fe9dba3413753c90b695ae75dccee5b3401e76df29b9d33a13900000efda51589f86e30cc2305e7388c01ce0309c19a182cf37bced97c7da72236f660c0a395e765e6e06962ecff5a69d7de359c348a574176c210c37a25d4ffd917866fb0a31976a914e54445646929fac8b7d6c71715913af44324978488ac00a5d7acb20a7aea830918f00bec115567e48a6300a26f2ffefd51e29d3e80c3411fa51861025bb5ff4ba4ad3be6090c4ba76b1671d70799ed6882c57bcfeaf27cbd558068e9b5fc1553abce8822fcee63e8f6fbb06ad5b753d47e794bfacadbde3f"
            )
        txdata = proto.SignTx()
        txdata.version = (3 << 16) | 3
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
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=221,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
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
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=221,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=221,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                self.client, "Dash Testnet", [inp1], [out1], details=txdata, prev_txes=TX_API, extra_payload=extra_payload
            )
        assert (
            serialized_tx.hex()
            == "03000300018dc5f38fcb801a6fad31de622a226e5b1886b1fecac41ada087d5c23be016e69010000006b483045022100af3d024f852dfc483f6dfa069b792d46bc1bb06f2f32469e1cfdf22ca74c9f25022053ebf8cc04357d32f321eb9a515d50eb4dc2bda7da3244dc41ad17d000bfa6d00121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff0186a4c872170000001976a914a579388225827d9f2fe9014add644487808c695d88ac00000000e4010061d48e8bd82f0fe9dba3413753c90b695ae75dccee5b3401e76df29b9d33a13900000efda51589f86e30cc2305e7388c01ce0309c19a182cf37bced97c7da72236f660c0a395e765e6e06962ecff5a69d7de359c348a574176c210c37a25d4ffd917866fb0a31976a914e54445646929fac8b7d6c71715913af44324978488ac00a5d7acb20a7aea830918f00bec115567e48a6300a26f2ffefd51e29d3e80c3411fa51861025bb5ff4ba4ad3be6090c4ba76b1671d70799ed6882c57bcfeaf27cbd558068e9b5fc1553abce8822fcee63e8f6fbb06ad5b753d47e794bfacadbde3f"
        )

    def test_send_dash_dip2_prouprevtx(self):
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
            address_n=parse_path("44'/1'/0'/0/0"),
            amount=100709999750,
            script_type=proto.OutputScriptType.PAYTOADDRESS,
        )
        extra_payload = bytes.fromhex(
                "a4010061d48e8bd82f0fe9dba3413753c90b695ae75dccee5b3401e76df29b9d33a139000000a5d7acb20a7aea830918f00bec115567e48a6300a26f2ffefd51e29d3e80c30de852c97297bbd9cedb79280f3f1e31b092904a8870274a5a0e52de2ae1dc0bad74851dc0a1e4fe4c274535a2422d3e1510a7be2fbecaae73128e8eb2f336382fb376d2f82273a72960980972b02e3ecf895c00187e0cbe735dc44cb3d97711"
            )
        txdata = proto.SignTx()
        txdata.version = (4 << 16) | 3
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
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=157,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
                    proto.ButtonRequest(code=proto.ButtonRequestType.SignTx),
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
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=157,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXOUTPUT,
                        details=proto.TxRequestDetailsType(request_index=0),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=8,
                            extra_data_offset=0,
                        ),
                    ),
                    proto.TxRequest(
                        request_type=proto.RequestType.TXEXTRADATA,
                        details=proto.TxRequestDetailsType(
                            extra_data_len=157,
                            extra_data_offset=8,
                        ),
                    ),
                    proto.TxRequest(request_type=proto.RequestType.TXFINISHED),
                ]
            )
            _, serialized_tx = btc.sign_tx(
                self.client, "Dash Testnet", [inp1], [out1], details=txdata, prev_txes=TX_API, extra_payload=extra_payload
            )
        assert (
            serialized_tx.hex()
            == "03000400018dc5f38fcb801a6fad31de622a226e5b1886b1fecac41ada087d5c23be016e69010000006b483045022100a50cb32cfe268eb9608406c469e60b16de7963824cf9399e83611c8a7b8515440220423a9133acac8ef2c4f330adc2af25441638987943b8c149b28959663b7a48d80121030e669acac1f280d1ddf441cd2ba5e97417bf2689e4bbec86df4f831bf9f7ffd0ffffffff0186a4c872170000001976a914a579388225827d9f2fe9014add644487808c695d88ac00000000a4010061d48e8bd82f0fe9dba3413753c90b695ae75dccee5b3401e76df29b9d33a139000000a5d7acb20a7aea830918f00bec115567e48a6300a26f2ffefd51e29d3e80c30de852c97297bbd9cedb79280f3f1e31b092904a8870274a5a0e52de2ae1dc0bad74851dc0a1e4fe4c274535a2422d3e1510a7be2fbecaae73128e8eb2f336382fb376d2f82273a72960980972b02e3ecf895c00187e0cbe735dc44cb3d97711"
        )

