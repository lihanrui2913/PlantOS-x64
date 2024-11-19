set_project("PlantOS")

add_rules("mode.debug", "mode.release")

set_optimize("none")

set_policy("run.autobuild", true)
set_policy("build.optimization.lto", true)

-- About KERNEL

target("kernel")
set_languages("c23")
set_kind("binary")
set_toolchains("gcc")
set_default(false)

add_includedirs("include")
add_files("src/**.S")
add_files("src/**.c")

add_cflags("-c", "-g", "-O0", "-m64", "-fno-builtin", "-fpic", "-fno-stack-protector", "-nostdlib", "-mcmodel=large")
add_ldflags("-nostdlib", "-T", "assets/linker.ld", {
    force = true
})

if is_mode("release") then
    set_symbols("debug")
end

-- About LIBC

target("c")
set_languages("c23")
set_kind("static")
set_toolchains("gcc")
set_default(false)

add_includedirs("usr/libc")
add_files("usr/libc/**.c")

add_cflags("-c", "-g", "-O0", "-m64", "-fno-builtin", "-fno-stack-protector", "-nostdlib", "-nostdinc")
add_ldflags("-nostdlib", "-static")

if is_mode("release") then
    set_symbols("debug")
end

-- About INIT

target("init")
add_deps("c")
set_languages("c23")
set_kind("binary")
set_toolchains("gcc")
set_default(false)

add_includedirs("usr/libc")
add_files("usr/apps/init/**.c")

add_cflags("-c", "-g", "-O0", "-m64", "-fno-builtin", "-fno-stack-protector", "-nostdlib", "-nostdinc")

if is_mode("release") then
    set_symbols("debug")
end

target("iso")
set_kind("phony")
add_deps("kernel")
add_deps("init")
set_default(true)

on_build(function(target)
    import("core.project.project")

    local iso_dir = "$(buildir)/iso"
    os.cp("assets/limine/*", iso_dir .. "/limine/")

    local target = project.target("kernel")
    os.cp(target:targetfile(), iso_dir .. "/kernel.elf")

    local iso_file = "$(buildir)/PlantOS.iso"
    os.run("xorriso -as mkisofs --efi-boot limine/limine-uefi-cd.bin %s -o %s", iso_dir, iso_file)
    os.run("assets/limine/limine bios-install %s", iso_file)
    print("ISO image created at: %s", iso_file)

    local target_init = project.target("init")

    os.run("bash tools/create_hdd_image.sh");
    os.run("sudo bash tools/mount_vdisk.sh");
    os.run("sudo cp " .. target_init:targetfile() .. " mnt_point/init.elf")
    os.run("sudo bash tools/umount_vdisk.sh");
end)

on_run(function(target)
    import("core.project.config")

    local flags = {"-M", "q35", "-m", "4G", "-smp", "4", "-bios", "/usr/share/ovmf/OVMF.fd", "-cdrom",
                   config.buildir() .. "/PlantOS.iso", "-drive",
                   "if=none,format=raw,id=root,file=" .. config.buildir() .. "/hdd.img", "-cpu", "IvyBridge,+x2apic",
                   "-device", "ahci,id=ahci", "-device", "ide-hd,drive=root,bus=ahci.1", "--enable-kvm"};

    local wsl = false;

    if wsl then
        os.runv("sudo qemu-system-x86_64", flags)
    else
        os.runv("qemu-system-x86_64", flags)

    end
end)
