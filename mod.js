// mod.js — Supreme Duelist unlimited money + level
// Tự động quét class IL2CPP, hook getter chứa từ khóa.

setTimeout(function() {
    Java.perform(function() {
        var il2cpp = Process.getModuleByName("libil2cpp.so");
        console.log("[+] libil2cpp.so @ " + il2cpp.base);

        var domain_get = new NativeFunction(il2cpp.getExportByName("il2cpp_domain_get"), 'pointer', []);
        var asm_open = new NativeFunction(il2cpp.getExportByName("il2cpp_domain_assembly_open"), 'pointer', ['pointer', 'pointer']);
        var asm_get_image = new NativeFunction(il2cpp.getExportByName("il2cpp_assembly_get_image"), 'pointer', ['pointer']);
        var image_get_class_count = new NativeFunction(il2cpp.getExportByName("il2cpp_image_get_class_count"), 'uint32', ['pointer']);
        var image_get_class = new NativeFunction(il2cpp.getExportByName("il2cpp_image_get_class"), 'pointer', ['pointer', 'uint32']);
        var class_get_name = new NativeFunction(il2cpp.getExportByName("il2cpp_class_get_name"), 'pointer', ['pointer']);
        var class_get_methods = new NativeFunction(il2cpp.getExportByName("il2cpp_class_get_methods"), 'pointer', ['pointer', 'pointer']);
        var method_get_name = new NativeFunction(il2cpp.getExportByName("il2cpp_method_get_name"), 'pointer', ['pointer']);
        var method_get_addr = new NativeFunction(il2cpp.getExportByName("il2cpp_method_get_address"), 'pointer', ['pointer']);

        var domain = domain_get();
        var asm = asm_open(domain, Memory.allocUtf8String("Assembly-CSharp.dll"));
        if (asm.isNull()) {
            console.log("[-] Assembly-CSharp.dll not found.");
            return;
        }
        var image = asm_get_image(asm);

        var classCount = image_get_class_count(image);
        console.log("[+] Classes in image: " + classCount);

        var keywords = ["money", "coin", "gold", "cash", "level", "score", "experience", "xp", "currency", "wallet", "gem", "diamond"];
        var hookedCount = 0;

        for (var i = 0; i < classCount; i++) {
            var klass = image_get_class(image, i);
            if (klass.isNull()) continue;
            var className = class_get_name(klass).readUtf8String();
            var lowerClassName = className.toLowerCase();
            var classMatches = keywords.some(function(kw) { return lowerClassName.indexOf(kw) !== -1; });
            if (!classMatches) continue;

            console.log("[*] Scanning class: " + className);
            var iter = Memory.alloc(Process.pointerSize);
            iter.writePointer(ptr(0));
            var method;
            while ((method = class_get_methods(klass, iter)) && !method.isNull()) {
                var methodName = method_get_name(method).readUtf8String();
                var lowerMethodName = methodName.toLowerCase();
                if (lowerMethodName.startsWith("get_")) {
                    var matches = keywords.some(function(kw) { return lowerMethodName.indexOf(kw) !== -1; });
                    if (matches) {
                        var addr = method_get_addr(method);
                        if (!addr.isNull()) {
                            console.log("[+] Hooking " + className + "." + methodName + " @ " + addr);
                            try {
                                Interceptor.attach(addr, {
                                    onLeave: function(retval) {
                                        retval.replace(ptr(999999999));
                                    }
                                });
                                hookedCount++;
                            } catch (e) {
                                console.log("[-] Failed to hook: " + e);
                            }
                        }
                    }
                }
            }
        }
        console.log("[+] Total hooked: " + hookedCount);
    });
}, 5000);
