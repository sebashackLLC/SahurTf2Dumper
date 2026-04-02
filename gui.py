import dearpygui.dearpygui as dpg
from dumper import TF2Dumper
import threading
import time
import os
import ctypes

class DumperGUI:
    def __init__(self):
        self.dumper = TF2Dumper()
        self.status = "Idle"
        self.offsets_text = ""
        self.script_dir = os.path.dirname(os.path.abspath(__file__))

    def play_sahur(self):
        try:
            mp3_path = os.path.join(self.script_dir, "tung-tung-sahur.mp3")
            if os.path.exists(mp3_path):
                ctypes.windll.winmm.mciSendStringW("close sahur", None, 0, 0)
                ctypes.windll.winmm.mciSendStringW(f'open "{mp3_path}" type mpegvideo alias sahur', None, 0, 0)
                ctypes.windll.winmm.mciSendStringW("setaudio sahur volume to 300", None, 0, 0)
                ctypes.windll.winmm.mciSendStringW("play sahur", None, 0, 0)
        except Exception as e:
            print(f"Error playing sound: {e}")
        
    def log(self, message):
        self.status = message
        dpg.set_value("status_text", f"Status: {message}")

    def update_offsets_display(self):
        display = "--- Static Offsets ---\n"
        for k, v in self.dumper.offsets.items():
            display += f"{k}: 0x{v:X}\n"
        display += "\n--- NetVars ---\n"
        for k, v in self.dumper.netvars.items():
            display += f"{k}: 0x{v:X}\n"
        dpg.set_value("offsets_display", display)

    def run_dump(self):
        self.log("Attaching to TF2...")
        if self.dumper.attach():
            self.log("Dumping offsets...")
            if self.dumper.dump():
                self.dumper.export_cpp()
                self.log("Done! Exported to offsets.h")
                self.update_offsets_display()
            else:
                self.log("Failed to dump offsets.")
        else:
            self.log("TF2 (64-bit) not found.")

    def start_dump_thread(self):
        self.play_sahur()
        threading.Thread(target=self.run_dump, daemon=True).start()

    def setup(self):
        dpg.create_context()
        
        script_dir = os.path.dirname(os.path.abspath(__file__))
        font_path = os.path.join(script_dir, "Comfortaa-SemiBold.ttf")
        bg_path = os.path.join(script_dir, "background.png")
        
        with dpg.font_registry():
            if os.path.exists(font_path):
                default_font = dpg.add_font(font_path, 18)
                dpg.bind_font(default_font)
        
        width, height, channels, data = dpg.load_image(bg_path)
        with dpg.texture_registry():
            dpg.add_static_texture(width, height, data, tag="bg_texture")

        with dpg.theme() as global_theme:
            with dpg.theme_component(dpg.mvAll):
                dpg.add_theme_color(dpg.mvThemeCol_WindowBg, (20, 20, 20, 150), category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_TitleBgActive, (45, 45, 45), category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_Button, (0, 0, 0, 0), category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_ButtonHovered, (255, 255, 255, 30), category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_ButtonActive, (255, 255, 255, 50), category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_Border, (255, 255, 255, 200), category=dpg.mvThemeCat_Core)
                dpg.add_theme_color(dpg.mvThemeCol_Text, (255, 255, 255), category=dpg.mvThemeCat_Core)
                
                dpg.add_theme_color(dpg.mvThemeCol_FrameBg, (0, 0, 0, 0), category=dpg.mvThemeCat_Core)
                
                dpg.add_theme_style(dpg.mvStyleVar_FrameBorderSize, 1)
                dpg.add_theme_style(dpg.mvStyleVar_WindowRounding, 0)
                dpg.add_theme_style(dpg.mvStyleVar_FrameRounding, 0)

        dpg.bind_theme(global_theme)

        with dpg.window(label="Sahur TF2 Dumper (64-bit)", width=600, height=650, no_collapse=True, no_move=True, no_title_bar=True, no_resize=True, no_scrollbar=True, no_scroll_with_mouse=True, pos=[0,0], tag="main_window"):
            dpg.add_image("bg_texture", width=600, height=650, pos=[0,0])
            
            with dpg.group(pos=[10, 10]):
                with dpg.group(horizontal=True):
                    dpg.add_text("Sahur TF2 Dumper (64-bit)", color=(0, 255, 127))
                    dpg.add_spacer(width=320)
                    dpg.add_button(label="X", callback=lambda: dpg.stop_dearpygui(), width=30, height=20)
                
                dpg.add_separator()
                
                dpg.add_spacer(height=10)
                dpg.add_button(label="Dump Offsets", callback=self.start_dump_thread, width=-1, height=40)
                
                dpg.add_spacer(height=10)
                dpg.add_text("Status: Idle", tag="status_text", color=(200, 200, 200))
                
                dpg.add_spacer(height=10)
                dpg.add_text("Discovered Offsets:")
                dpg.add_input_text(multiline=True, readonly=True, tag="offsets_display", width=580, height=450)
                
                dpg.add_spacer(height=10)
                dpg.add_text("Sahur Project", color=(100, 100, 100), indent=250)

        dpg.create_viewport(title='Sahur Dumper', width=600, height=650, resizable=False, decorated=False)
        dpg.setup_dearpygui()
        dpg.show_viewport()
        dpg.start_dearpygui()
        dpg.destroy_context()

if __name__ == "__main__":
    gui = DumperGUI()
    gui.setup()
