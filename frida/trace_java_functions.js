'use strict';

function bytes2hex(array) {
    var result = '';
    for(var i = 0; i < array.length; ++i)
        result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
    result += ' (' + array.length + ' bytes)'
    return result;
}

function jhexdump(array) {
    var ptr = Memory.alloc(array.length);
    for(var i = 0; i < array.length; ++i)
        Memory.writeS8(ptr.add(i), array[i]);
    return hexdump(ptr, { offset: 0, length: array.length, header: false, ansi: false });
}

Java.perform(
    function() {
        var Cipher = Java.use('javax.crypto.Cipher');
        Cipher
            .doFinal
            .overload('[B')
            .implementation = function(barr)
        {
            var retval = this.doFinal(barr);
            console.log(
                '[+] doFinal(' + barr.$handle +
                ') -> ' + retval.$handle
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('retv : ' + jhexdump(retval));

            return retval;
        };

        var SecretKeySpec = Java.use(
            'javax.crypto.spec.SecretKeySpec'
        );
        SecretKeySpec
            .$init
            .overload('[B', 'java.lang.String')
            .implementation = function(barr, s) {
            console.log(
                '[+] new SecretKeySpec(' + barr.$handle +
                ', "' + s + '")'
            );
            console.log('barr : ' + jhexdump(barr));
            return this.$init(barr, s);
        };

        var DoorLockNdk = Java.use(
            'com.guardtec.keywe.sdk.doorlock.device.DoorLockNdk'
        );

        DoorLockNdk.doorOpen.implementation = function(param) {
            var retval = this.doorOpen(param);
            console.log('[+] doorOpen(' + param + ') -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorClose.implementation = function() {
            var retval = this.doorClose();
            console.log('[+] doorClose() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorOneTouch.implementation = function(param) {
            var retval = this.doorOneTouch(param);
            console.log('[+] doorOneTouch(' + param + ') -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorStatus.implementation = function() {
            var retval = this.doorStatus();
            console.log('[+] doorStatus() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorDeviceInfoGet.implementation = function() {
            var retval = this.doorDeviceInfoGet();
            console.log('[+] doorDeviceInfoGet() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorMode.implementation = function() {
            var retval = this.doorMode();
            console.log('[+] doorMode() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorEnterCount.implementation = function() {
            var retval = this.doorEnterCount();
            console.log('[+] doorEnterCount() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.makeDoorKey.implementation = function(barr, barr2) {
            var retval = this.makeDoorKey(barr, barr2);
            console.log(
                '[+] makeDoorKey(' +
                barr.$handle + ', ' + barr2.$handle +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('barr2: ' + jhexdump(barr2));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.makeAppKey.implementation = function(barr, barr2) {
            var retval = this.makeAppKey(barr, barr2);
            console.log(
                '[+] makeAppKey(' +
                barr.$handle + ', ' + barr2.$handle +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('barr2: ' + jhexdump(barr2));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.makeCommonKey.implementation = function(barr) {
            var retval = this.makeCommonKey(barr);
            console.log(
                '[+] makeCommonKey(' +
                barr.$handle +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.isHello.implementation = function(barr) {
            var retval = this.isHello(barr);
            console.log(
                '[+] isHello(' +
                barr.$handle +
                ') -> ' + retval
            );
            console.log('barr : ' + jhexdump(barr));
            return retval;
        };
        DoorLockNdk.isStart.implementation = function(barr) {
            var retval = this.isStart(barr);
            console.log(
                '[+] isStart(' +
                barr.$handle +
                ') -> ' + retval
            );
            console.log('barr : ' + jhexdump(barr));
            return retval;
        };
        DoorLockNdk.makeAppNumber.implementation = function() {
            var retval = this.makeAppNumber();
            console.log('[+] makeAppNumber() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.makeWelcome.implementation = function() {
            var retval = this.makeWelcome();
            console.log('[+] makeWelcome() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        }; 
        DoorLockNdk.disConnect.implementation = function() {
            var retval = this.disConnect();
            console.log('[+] disConnect() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorBanksInfo.implementation = function() {
            var retval = this.doorBanksInfo();
            console.log('[+] doorBanksInfo() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.eKeyClear.implementation = function() {
            var retval = this.eKeyClear();
            console.log('[+] eKeyClear() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorOneTimePasswordClear.implementation = function() {
            var retval = this.doorOneTimePasswordClear();
            console.log('[+] doorOneTimePasswordClear() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorOneTimePasswordConfirm.implementation = function() {
            var retval = this.doorOneTimePasswordConfirm();
            console.log('[+] doorOneTimePasswordConfirm() -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorBankCardDel.implementation = function(param) {
            var retval = this.doorBankCardDel(param);
            console.log('[+] doorBankCardDel(' + param + ') -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorBankPassCodeDel.implementation = function(param) {
            var retval = this.doorBankPassCodeDel(param);
            console.log('[+] doorBankPassCodeDel(' + param + ') -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorBankPassCodeGet.implementation = function(param) {
            var retval = this.doorBankPassCodeGet(param);
            console.log('[+] doorBankPassCodeGet(' + param + ') -> ');
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorTimeSet.implementation = function(barr, barr2) {
            var retval = this.doorTimeSet(barr, barr2);
            console.log(
                '[+] doorTimeSet(' +
                barr.$handle + ', ' + barr2.$handle +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('barr2: ' + jhexdump(barr2));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorOTPKeySet.implementation = function(barr) {
            var retval = this.doorOTPKeySet(barr);
            console.log(
                '[+] doorOTPKeySet(' +
                barr.$handle +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorPwdSet.implementation = function(barr) {
            var retval = this.doorPwdSet(barr);
            console.log(
                '[+] doorPwdSet(' +
                barr.$handle +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.eKeyRegister.implementation = function(barr) {
            var retval = this.eKeyRegister(barr);
            console.log(
                '[+] eKeyRegister(' +
                barr.$handle +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.eKeyRenewal.implementation = function(barr) {
            var retval = this.eKeyRenewal(barr);
            console.log(
                '[+] eKeyRenewal(' +
                barr.$handle +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.eKeyVerify.implementation = function(barr) {
            var retval = this.eKeyVerify(barr);
            console.log(
                '[+] eKeyVerify(' +
                barr.$handle +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorOneTimePasswordSet.implementation = function(barr) {
            var retval = this.doorOneTimePasswordSet(barr);
            console.log(
                '[+] doorOneTimePasswordSet(' +
                barr.$handle +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorDeviceInfoSet.implementation = function(param1, param2, param3, param4) {
            var retval = this.doorDeviceInfoSet(
                param1,
                param2,
                param3,
                param4
            );
            console.log(
                '[+] doorDeviceInfoSet(' +
                param1 + ', ' +
                param2 + ', ' +
                param3 + ', ' +
                param4 +
                ') -> '
            );
            console.log('    ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorBankCardSet.implementation = function(barr, b) {
            var retval = this.doorBankCardSet(barr, b);
            console.log(
                '[+] doorBankCardSet(' +
                barr.$handle + ', ' + b +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorBankNFCCardSet.implementation = function(barr, b) {
            var retval = this.doorBankNFCCardSet(barr, b);
            console.log(
                '[+] doorBankNFCCardSet(' +
                barr.$handle + ', ' + b +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
        DoorLockNdk.doorBankPassCodeSet.implementation = function(barr, b) {
            var retval = this.doorBankPassCodeSet(barr, b);
            console.log(
                '[+] doorBankPassCodeSet(' +
                barr.$handle + ', ' + b +
                ') -> '
            );
            console.log('barr : ' + jhexdump(barr));
            console.log('retv : ' + jhexdump(retval));
            return retval;
        };
    }
);
