/*
 * KeyWe root detection evasion
 * it's fairly easy to do, since there's just one function
 * com.guardtec.keywe.util.RootTool.isRooted that takes no
 * args and returns a boolean ;-)
 * */
Java.perform(
    function() {
        console.log('[ ] Attempting to replace the isRooted() func...');
        var RootTool = Java.use(
            'com.guardtec.keywe.util.RootTool'
        );
        RootTool.isRooted.implementation = function() {
            console.log('[*] You shall not pass!');
            return false;
        };
        console.log('[+] Replaced! Hasta la vista, wololo!');
    }
);
