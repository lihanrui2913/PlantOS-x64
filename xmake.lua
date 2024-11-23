set_project("PlantOS")

add_rules("mode.debug", "mode.release")
add_requires("zig")
set_defaultmode("debug")

set_optimize("none")
set_languages("c23")

set_policy("run.autobuild", true)
set_policy("check.auto_ignore_flags", false)

add_cflags("-target x86_64-freestanding")
add_arflags("-target x86_64-freestanding")
add_ldflags("-target x86_64-freestanding")

add_cflags("-mno-80387", "-mno-mmx", "-mno-sse", "-mno-sse2", "-msoft-float")
add_cflags("-mno-red-zone", "-mcmodel=large", "-fno-sanitize=undefined")

target("kernel")
set_kind("binary")
set_toolchains("@zig")
set_default(false)

add_linkdirs("libs")
add_includedirs("include")
add_ldflags("-T assets/linker.ld", "-e kmain")

add_links("plalloc")
add_links("os_terminal")
add_files("src/**.S", "src/**.c")

target("libc")
set_kind("static")
set_toolchains("@zig")
set_default(false)

add_includedirs("usr/libc")
add_files("usr/libc/**.c")

target("init")
add_deps("libc")
set_kind("binary")
set_toolchains("@zig")
set_default(false)

add_includedirs("usr/libc")
add_files("usr/apps/init/**.c")

target("disk")
set_kind("phony")
add_deps("kernel")
add_deps("init")
set_default(true)

on_build(function(target)
    import("core.project.project")

    local kernel_target = project.target("kernel")
    local init_target = project.target("init")
    os.run("bash tools/create_hdd_image.sh")
    os.run("sudo bash tools/mount_vdisk.sh")
    os.run("sudo cp " .. kernel_target:targetfile() .. " mnt_point/kernel.elf")
    os.run("sudo cp " .. init_target:targetfile() .. " mnt_point/init.elf")
    os.run("sudo bash tools/umount_vdisk.sh")
    os.run("assets/limine/limine bios-install build/hdd.img")
end)

on_run(function(target)
    import("core.project.config")

    local flags = {"-M", "q35", "-m", "8g", "-smp", "4", "-drive", "if=pflash,format=raw,file=assets/ovmf-code.fd",
                   "-cpu", "IvyBridge,+x2apic", "-drive",
                   "if=none,format=raw,id=root,file=" .. config.buildir() .. "/hdd.img", "-device", 
                   "nvme,drive=root,serial=1234", "--enable-kvm"};

    os.execv("sudo qemu-system-x86_64", flags)
end)
