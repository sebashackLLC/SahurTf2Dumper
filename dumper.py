import pymem
import pymem.process
import pymem.pattern
import re
import os

class NetvarManager:
    last_found_netvars = {}
    last_found_class_ids = {}
    
    def __init__(self, pm, client_base, client_module):
        self.pm = pm
        self.client_base = client_base
        self.client_module = client_module
        self.netvars = {}
        self.class_ids = {}

    def get_client_class_head_via_interface(self):
        try:
            pass
        except:
            pass
        return 0

    def get_client_class_head(self):
        pattern = b"\x48\x8B\x05....\xC3"
        addresses = pymem.pattern.pattern_scan_module(self.pm.process_handle, self.client_module, pattern, return_multiple=True)
        
        if not addresses:
            return 0
            
        for addr in addresses:
            rel = self.pm.read_int(addr + 3)
            head_ptr_ptr = addr + 7 + rel
            
            try:
                head_ptr = self.pm.read_longlong(head_ptr_ptr)
                if head_ptr == 0: continue
                
                name_ptr = self.pm.read_longlong(head_ptr + 0x10)
                if name_ptr < self.client_base or name_ptr > self.client_base + 0xFFFFFFF: continue
                
                name = self.pm.read_string(name_ptr, 32)
                
                if name.startswith('C') and any(c.isupper() for c in name[1:]):
                    next_ptr = self.pm.read_longlong(head_ptr + 0x20)
                    if next_ptr == 0 or (next_ptr > self.client_base and next_ptr < self.client_base + 0xFFFFFFF):
                        return head_ptr_ptr
            except:
                continue
        return 0

    def dump_vars(self):
        head_ptr = self.get_client_class_head()
        if not head_ptr:
            return False
            
        client_class = self.pm.read_longlong(head_ptr)
        while client_class:
            recv_table = self.pm.read_longlong(client_class + 0x18)
            if recv_table:
                table_name_ptr = self.pm.read_longlong(recv_table + 0x18)
                table_name = self.pm.read_string(table_name_ptr, 128)
                self.dump_table(recv_table, table_name)
            client_class = self.pm.read_longlong(client_class + 0x20)
        return True

    def dump_table(self, table_addr, table_name):
        num_props = self.pm.read_int(table_addr + 0x8)
        props_addr = self.pm.read_longlong(table_addr)
        
        for i in range(num_props):
            prop_addr = props_addr + (i * 0x60)
            prop_name_ptr = self.pm.read_longlong(prop_addr)
            if not prop_name_ptr: continue
            
            prop_name = self.pm.read_string(prop_name_ptr, 128)
            offset = self.pm.read_int(prop_addr + 0x48)
            
            if offset != 0:
                self.netvars[f"{table_name}->{prop_name}"] = offset
                NetvarManager.last_found_netvars[f"{table_name}->{prop_name}"] = offset
                
                if prop_name not in self.netvars:
                    self.netvars[prop_name] = offset
            
            child_table = self.pm.read_longlong(prop_addr + 0x40)
            if child_table:
                self.dump_table(child_table, table_name)

    def dump_class_ids(self):
        head_ptr = self.get_client_class_head()
        if not head_ptr:
            return False
            
        client_class = self.pm.read_longlong(head_ptr)
        while client_class:
            try:
                name_ptr = self.pm.read_longlong(client_class + 0x10)
                name = self.pm.read_string(name_ptr, 128)
                class_id = self.pm.read_int(client_class + 0x28)
                if name and class_id > 0:
                    self.class_ids[name] = class_id
                    NetvarManager.last_found_class_ids[name] = class_id
            except:
                break
            client_class = self.pm.read_longlong(client_class + 0x20)
        return True

class TF2Dumper:
    def __init__(self):
        self.pm = None
        self.client = None
        self.engine = None
        self.client_base = 0
        self.engine_base = 0
        self.offsets = {}
        self.netvars = {}
        self.class_ids = {}
        
    def attach(self):
        try:
            self.pm = pymem.Pymem("tf_win64.exe")
            self.client = pymem.process.module_from_name(self.pm.process_handle, "client.dll")
            self.engine = pymem.process.module_from_name(self.pm.process_handle, "engine.dll")
            self.client_base = self.client.lpBaseOfDll
            self.engine_base = self.engine.lpBaseOfDll
            return True
        except Exception as e:
            print(f"Error attaching: {e}")
            return False

    def get_rip_relative(self, address, offset, length, module_base=None):
        if module_base is None: module_base = self.client_base
        relative_offset = self.pm.read_int(address + offset)
        return (address + length + relative_offset) - module_base

    def scan_client(self, pattern):
        if isinstance(pattern, str):
            pattern = self.regex_from_hex(pattern)
        return pymem.pattern.pattern_scan_module(self.pm.process_handle, self.client, pattern)

    def scan_engine(self, pattern):
        if isinstance(pattern, str):
            pattern = self.regex_from_hex(pattern)
        return pymem.pattern.pattern_scan_module(self.pm.process_handle, self.engine, pattern)

    def regex_from_hex(self, hex_str):
        import re
        parts = hex_str.split()
        regex_parts = []
        for p in parts:
            if p == "??":
                regex_parts.append(b".")
            else:
                regex_parts.append(re.escape(bytes.fromhex(p)))
        return b"".join(regex_parts)

    def dump(self):
        if not self.pm:
            return False

        found_any = False
        
        lp_sigs = [
            "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 ?? 48 8B 01 FF 90 ?? ?? ?? ?? 48 8B C8",
            "48 8B 05 ?? ?? ?? ?? 48 8B 80 ?? ?? ?? ?? 48 85 C0 74 07",
            "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 05 E8 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ??",
            "48 8B 0D ?? ?? ?? ?? 48 85 C9 74 0A 48 8B 01 FF 90",
            "48 8B 05 ?? ?? ?? ?? 48 85 C0 74 08 48 8B 80 ?? ?? ?? ?? 48 85 C0"
        ]
        for sig in lp_sigs:
            lp_addr = self.scan_client(sig)
            if lp_addr:
                self.offsets["dwLocalPlayer"] = self.get_rip_relative(lp_addr, 3, 7)
                found_any = True
                break
        
        if "dwEntityList" not in self.offsets or self.offsets["dwEntityList"] == 0:
            ent_pattern = "48 8D 0D ?? ?? ?? ?? E8 ?? ?? ?? ?? 48 8B D8 48 85 C0 74 0A"
            ent_addr = self.scan_client(ent_pattern)
            if ent_addr:
                self.offsets["dwEntityList"] = self.get_rip_relative(ent_addr, 3, 7)
                found_any = True

        vm_sigs = [
            "48 8D 0D ?? ?? ?? ?? 48 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ??",
            "48 8B 05 ?? ?? ?? ?? 48 8D 4C 24 ?? 4C 8D 05 ?? ?? ?? ??",
            "48 8D 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 4C 8D 05 ?? ?? ?? ??"
        ]
        for sig in vm_sigs:
            vm_addr = self.scan_engine(sig)
            if vm_addr:
                self.offsets["dwViewMatrix"] = self.get_rip_relative(vm_addr, 3, 7, self.engine_base)
                found_any = True
                break
            vm_addr = self.scan_client(sig)
            if vm_addr:
                self.offsets["dwViewMatrix"] = self.get_rip_relative(vm_addr, 3, 7, self.client_base)
                found_any = True
                break

        glow_sigs = [
            "48 8B 05 ?? ?? ?? ?? 48 8B D1 48 8B 0C C8 48 85 C9 74 0A",
            "48 8D 05 ?? ?? ?? ?? C3 CC CC CC CC CC CC CC 48 8D 05",
            "48 8B 05 ?? ?? ?? ?? 48 89 05 ?? ?? ?? ?? 48 8B 0D"
        ]
        for sig in glow_sigs:
            glow_addr = self.scan_client(sig)
            if glow_addr:
                self.offsets["dwGlowObjectManager"] = self.get_rip_relative(glow_addr, 3, 7)
                found_any = True
                break

        buttons = {
            "dwForceAttack": "89 05 ?? ?? ?? ?? 48 8B 05 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? FF 50 28",
            "dwForceJump": "48 8B 05 ?? ?? ?? ?? 48 8D 15 ?? ?? ?? ?? 48 89 44 24 ?? E8 ?? ?? ?? ?? 48 8B 0D",
            "dwForceBackward": "48 8B 05 ?? ?? ?? ?? 44 8B 0D ?? ?? ?? ?? 83 CA FF",
            "dwForceForward": "48 8B 05 ?? ?? ?? ?? 44 8B 0D ?? ?? ?? ?? 83 CA 01",
        }
        for name, sig in buttons.items():
            addr = self.scan_client(sig)
            if addr:
                self.offsets[name] = self.get_rip_relative(addr, 3, 7)
                found_any = True

        nvm = NetvarManager(self.pm, self.client_base, self.client)
        if nvm.dump_vars():
            requested_vars = [
                "m_iHealth", "m_iMaxHealth", "m_iTeamNum", "m_vecOrigin", 
                "m_lifeState", "m_iClass", "m_bDormant", "m_hOwnerEntity",
                "m_pBoneMatrix", "m_vecViewOffset", "m_nModelIndex", "m_fFlags",
                "m_iObjectType", "m_iUpgradeLevel", "m_nForceBone", "m_vecViewOffset[0]",
                "m_hMyWeapons", "m_iItemDefinitionIndex", "m_nSequence", "m_flCycle",
                "m_bSpottedByMask", "m_angEyeAngles", "m_nPlayerCond", "m_nCondBits"
            ]
            for var in requested_vars:
                match = None
                if var in nvm.netvars:
                    match = var
                else:
                    for full_name in nvm.netvars:
                        if full_name.endswith(f"->{var}"):
                            match = full_name
                            break
                
                if match:
                    self.netvars[var] = nvm.netvars[match]
            
            if "m_bDormant" not in self.netvars:
                pass
                
            found_any = True

        if nvm.dump_class_ids():
            self.class_ids = nvm.class_ids
            found_any = True

        return found_any

    def export_cpp(self, filename="offsets.h"):
        script_dir = os.path.dirname(os.path.abspath(__file__))
        full_path = os.path.join(script_dir, filename)
        log_path = os.path.join(script_dir, "all_netvars.txt")
        
        with open(log_path, "w") as f:
            for k, v in sorted(NetvarManager.last_found_netvars.items()):
                f.write(f"{k} = 0x{v:X}\n")
            f.write("\n--- Class IDs ---\n")
            for k, v in sorted(NetvarManager.last_found_class_ids.items()):
                f.write(f"{k} = {v}\n")

        content = "#pragma once\n\nnamespace offsets {\n"
        content += "    // Static Offsets\n"
        for key, value in sorted(self.offsets.items()):
            content += f"    constexpr ptrdiff_t {key} = 0x{value:X};\n"
        content += "\n    // NetVars\n"
        for key, value in sorted(self.netvars.items()):
            content += f"    constexpr ptrdiff_t {key} = 0x{value:X};\n"
        
        content += "\n    // Entity Class IDs\n"
        for key, value in sorted(self.class_ids.items()):
            content += f"    constexpr int {key} = {value};\n"
            
        content += "}\n"
        
        with open(full_path, "w") as f:
            f.write(content)
        return full_path

if __name__ == "__main__":
    dumper = TF2Dumper()
    if dumper.attach():
        if dumper.dump():
            print("Offsets found:")
            for k, v in dumper.offsets.items():
                print(f"{k}: 0x{v:X}")
            path = dumper.export_cpp()
            print(f"Exported to {path}")
        else:
            print("Failed to dump offsets.")
    else:
        print("TF2 (64-bit) not found.")
