// mod.js — Supreme Duelist unlimited money + level
// Frida Gadget payload. Quét class IL2CPP, hook mọi getter chứa từ khóa,
// ép return value về số lớn. Không cần root.

setTimeout(function() {
    Java.perform(function() {
        var il2cpp;
        try {
            il2cpp = Process.getModuleByName("libil2cpp.so");
        } catch (e) {
            console.log("[-] libil2cpp.so not loaded yet");
            return;
        }
        console.log("[+] libil2cpp.so @ " + il2cpp.base);

        function exp(name) {
            var p = il2cpp.findExportByName(name);
            if (p === null) throw new Error("missing export: " + name);
            return p;
        }

        var domain_get            = new NativeFunction(exp("il2cpp_domain_get"), 'pointer', []);
        var asm_open              = new NativeFunction(exp("il2cpp_domain_assembly_open"), 'pointer', ['pointer', 'pointer']);
        var asm_get_image         = new NativeFunction(exp("il2cpp_assembly_get_image"), 'pointer', ['pointer']);
        var image_get_class_count = new NativeFunction(exp("il2cpp_image_get_class_count"), 'uint32', ['pointer']);
        var image_get_class       = new NativeFunction(exp("il2cpp_image_get_class"), 'pointer', ['pointer', 'uint32']);
        var class_get_name        = new NativeFunction(exp("il2cpp_class_get_name"), 'pointer', ['pointer']);
        var class_get_methods     = new NativeFunction(exp("il2cpp_class_get_methods"), 'pointer', ['pointer', 'pointer']);
        var method_get_name       = new NativeFunction(exp("il2cpp_method_get_name"), 'pointer', ['pointer']);
        var method_get_addr       = new NativeFunction(exp("il2cpp_method_get_address"), 'pointer', ['pointer']);

        var domain = domain_get();
        var asm = asm_open(domain, Memory.allocUtf8String("Assembly-CSharp.dll"));
        if (asm.isNull()) {
            console.log("[-] Assembly-CSharp.dll not found");
            return;
        }
        var image = asm_get_image(asm);
        var classCount = image_get_class_count(image);
        console.log("[+] Classes in image: " + classCount);

        var keywords = [
            "money", "coin", "gold", "cash", "gem", "diamond",
            "level", "score", "experience", "xp", "currency", "wallet"
        ];

        var hookedCount = 0;

        for (var i = 0; i < classCount; i++) {
            var klass = image_get_class(image, i);
            if (klass.isNull()) continue;

            var className = class_get_name(klass).readUtf8String();
            var iter = Memory.alloc(Process.pointerSize);
            iter.writePointer(ptr(0));
            var method;

            while (!(method = class_get_methods(klass, iter)).isNull()) {
                var methodName = method_get_name(method).readUtf8String();
                var lm = methodName.toLowerCase();

                if (lm.indexOf("get_") !== 0) continue;

                var hit = keywords.some(function(kw) { return lm.indexOf(kw) !== -1; });
                if (!hit) continue;

                var addr = method_get_addr(method);
                if (addr.isNull()) continue;

                try {
                    (function(cls, mth, a) {
                        Interceptor.attach(a, {
                            onLeave: function(retval) {
                                retval.replace(ptr(999999999));
                            }
                        });
                        console.log("[+] hooked " + cls + "." + mth + " @ " + a);
                    })(className, methodName, addr);
                    hookedCount++;
                } catch (e) {
                    console.log("[-] hook fail " + className + "." + methodName + ": " + e);
                }
            }
        }
        console.log("[+] Total hooked getters: " + hookedCount);
    });
}, 5000);
