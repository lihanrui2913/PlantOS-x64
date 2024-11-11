set_project("PlantOS")

add_rules("mode.debug", "mode.release")

set_optimize("none")

set_policy("run.autobuild", true)
set_policy("build.optimization.lto", true)

target("kernel")
set_languages("c23")
set_kind("binary")
set_toolchains("gcc")
set_default(false)

add_includedirs("include")
add_files("src/**.S")
add_files("src/**.c")

add_cflags("-g", "-O0", "-m64", "-fno-builtin", "-fno-stack-protector", "-nostdlib", "-mcmodel=large")
add_ldflags("-nostdlib", "-static", "-T", "assets/linker.ld", {
    force = true
})

if is_mode("release") then
    set_symbols("debug")
end

target("iso")
set_kind("phony")
add_deps("kernel")
set_default(true)

on_build(function(target)
    import("core.project.project")

    local iso_dir = "$(buildir)/iso"
    os.cp("assets/limine/*", iso_dir .. "/limine/")

    local target = project.target("kernel")
    os.cp(target:targetfile(), iso_dir .. "/kernel.elf")

    local iso_file = "$(buildir)/PlantOS.iso"
    os.run("xorriso -as mkisofs --efi-boot limine/limine-uefi-cd.bin %s -o %s", iso_dir, iso_file)
    print("ISO image created at: %s", iso_file)
end)

on_run(function(target)
    import("core.project.config")

    local flags = {"-M", "q35", "-m", "8G", "-smp", "4", "-drive", "if=pflash,format=raw,file=assets/ovmf-code.fd",
                   "-cdrom", config.buildir() .. "/PlantOS.iso", "--enable-kvm", "-device", "ahci,id=ahci", "-device",
                   "ide-cd,bus=ahci.1"};

    local wsl = true;

    if wsl then
        os.runv("sudo qemu-system-x86_64", flags)
    else
        os.runv("qemu-system-x86_64", flags)

    end
end)
