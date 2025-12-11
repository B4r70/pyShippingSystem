""" 
//----------------------------------------------------------------------------------/
// # TCP-Receiver-Tool                                                              /
// ---------------------------------------------------------------------------------/
// Abschnitt . . : Communication Tools                                              /
// Datei . . . . : pyShippingSystem.py                                              /
// Autor . . . . : Bartosz Stryjewski                                               /
// Erstellt am . : 10.12.2025                                                       /
// Beschreibung  : Tool empfängt XML und generiert Versandeinheitennummern      /
// ---------------------------------------------------------------------------------/
// (C) Copyright by Bartosz Stryjewski                                              /
// ---------------------------------------------------------------------------------/
"""
import socket
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import xml.dom.minidom
import os
import re

class XMLTCPServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("pyShippingSystem")
        self.root.geometry("900x700")
        
        self.server_socket = None
        self.server_thread = None
        self.is_running = False
        
        self.create_widgets()
        
    def create_widgets(self):
        """
        Erstellt die GUI-Elemente
        """
        
        # Header Frame
        header_frame = ttk.Frame(self.root, padding="10")
        header_frame.pack(fill=tk.X)
        
        # Port-Eingabe
        ttk.Label(header_frame, text="Port:", font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        
        self.port_entry = ttk.Entry(header_frame, width=10, font=('Arial', 10))
        self.port_entry.insert(0, "8888")
        self.port_entry.pack(side=tk.LEFT, padx=5)
        
        # Bind Button
        self.bind_button = ttk.Button(
            header_frame, 
            text="Bind", 
            command=self.toggle_server,
            width=12
        )
        self.bind_button.pack(side=tk.LEFT, padx=5)
        
        # Status Label
        self.status_label = ttk.Label(
            header_frame, 
            text="● Gestoppt", 
            foreground="red",
            font=('Arial', 10, 'bold')
        )
        self.status_label.pack(side=tk.LEFT, padx=20)
        
        # Export Button
        self.export_button = ttk.Button(
            header_frame,
            text="Export",
            command=self.export_to_file,
            width=10
        )
        self.export_button.pack(side=tk.RIGHT, padx=5)
        
        # Clear Button
        self.clear_button = ttk.Button(
            header_frame,
            text="Clear",
            command=self.clear_output,
            width=10
        )
        self.clear_button.pack(side=tk.RIGHT, padx=5)
        
        # Separator
        ttk.Separator(self.root, orient='horizontal').pack(fill=tk.X, pady=5)
        
        # Text-Ausgabe Frame
        output_frame = ttk.Frame(self.root, padding="10")
        output_frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(output_frame, text="Empfangene Daten:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
        # Scrollbares Textfeld (monospaced)
        self.output_text = scrolledtext.ScrolledText(
            output_frame,
            wrap=tk.NONE,
            font=('Courier New', 9),
            bg='#1e1e1e',
            fg='#00ff00',
            insertbackground='white',
            state='disabled'
        )
        self.output_text.pack(fill=tk.BOTH, expand=True, pady=5)
        
        # Footer mit Statistik
        footer_frame = ttk.Frame(self.root, padding="10")
        footer_frame.pack(fill=tk.X)
        
        self.stats_label = ttk.Label(
            footer_frame,
            text="Empfangene Nachrichten: 0",
            font=('Arial', 9)
        )
        self.stats_label.pack(side=tk.LEFT)
        
        self.message_count = 0
        
    def toggle_server(self):
        """Startet oder stoppt den Server"""
        if not self.is_running:
            self.start_server()
        else:
            self.stop_server()
    
    def start_server(self):
        """Startet den TCP-Server"""
        try:
            port = int(self.port_entry.get())
            
            if port < 1 or port > 65535:
                messagebox.showerror("Fehler", "Port muss zwischen 1 und 65535 liegen")
                return
            
            # Socket erstellen und binden
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind(('0.0.0.0', port))
            self.server_socket.listen(5)
            
            self.is_running = True
            
            # Server-Thread starten
            self.server_thread = threading.Thread(target=self.run_server, daemon=True)
            self.server_thread.start()
            
            # GUI aktualisieren
            self.bind_button.config(text="Unbind")
            self.status_label.config(text="● Läuft", foreground="green")
            self.port_entry.config(state='disabled')
            
            self.log_message(f"Server gestartet auf Port {port}\n")
            self.log_message("Warte auf Verbindungen...\n")
            
        except ValueError:
            messagebox.showerror("Fehler", "Bitte eine gültige Portnummer eingeben")
        except OSError as e:
            messagebox.showerror("Fehler", f"Port bereits in Verwendung:\n{e}")
        except Exception as e:
            messagebox.showerror("Fehler", f"Server-Start fehlgeschlagen:\n{e}")
    
    def stop_server(self):
        """Stoppt den TCP-Server"""
        self.is_running = False
        
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        # GUI aktualisieren
        self.bind_button.config(text="Bind")
        self.status_label.config(text="● Gestoppt", foreground="red")
        self.port_entry.config(state='normal')
        
        self.log_message("Server gestoppt\n")
    
    def run_server(self):
        """Server-Loop für eingehende Verbindungen"""
        while self.is_running:
            try:
                self.server_socket.settimeout(1.0)
                client_socket, client_address = self.server_socket.accept()
                
                # Client in separatem Thread behandeln
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.is_running:
                    self.log_message(f"Server-Fehler: {e}\n")
                break
    
    def handle_client(self, client_socket, client_address):
        """Verarbeitet einzelne Client-Verbindung"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_message(f"\n{'='*70}\n")
        self.log_message(f"[{timestamp}] Neue Verbindung von {client_address[0]}:{client_address[1]}\n")
        self.log_message(f"{'='*70}\n")
        
        buffer = ""
        last_data_time = datetime.now()
        
        try:
            client_socket.settimeout(1.0)
            
            while self.is_running:
                try:
                    chunk = client_socket.recv(4096)
                    
                    if not chunk:
                        break
                    
                    buffer += chunk.decode('utf-8', errors='replace')
                    last_data_time = datetime.now()
                    
                except socket.timeout:
                    time_since_last_data = (datetime.now() - last_data_time).total_seconds()
                    
                    # Warte 2 Sekunden UND prüfe ob XML vollständig ist
                    if time_since_last_data >= 2.0 and buffer.strip() and '</LFS>' in buffer:
                        self.process_buffer(buffer, client_socket)
                        buffer = ""
                    
                    continue
                        
        except Exception as e:
            self.log_message(f"Fehler: {e}\n")
        finally:
            if buffer.strip():
                self.process_buffer(buffer, client_socket)
            
            client_socket.close()
            self.log_message(f"Verbindung zu {client_address[0]}:{client_address[1]} geschlossen\n")
    
    def process_buffer(self, buffer, client_socket):
        """Verarbeitet Buffer und extrahiert XMLs"""
        timestamp = datetime.now().strftime("%H:%M:%S")

        # Bereinige Buffer
        buffer = buffer.strip()

        if not buffer:
            return
        try:
            # Entferne BOM (Byte Order Mark) falls vorhanden
            if buffer.startswith('\ufeff'):
                buffer = buffer[1:]

            # AGGRESSIVE Bereinigung: Entferne ALLES vor <?xml
            xml_start = buffer.find('<?xml')
            if xml_start > 0:
                buffer = buffer[xml_start:]
            elif xml_start == -1:
                # Kein <?xml gefunden - ungültig
                self.log_message(f"\n[{timestamp}] ✗ Kein <?xml gefunden im Buffer\n\n")
                return
    
            # WICHTIG: Ersetze \r durch \n für korrektes XML-Parsing
            buffer = buffer.replace('\r', '\n')
            
            # WICHTIG: Schneide alles NACH </LFS> ab!
            lfs_end = buffer.find('</LFS>')
            if lfs_end != -1:
                buffer = buffer[:lfs_end + 6]  # +6 für die Länge von "</LFS>"
        
            # XML parsen und formatieren
            dom = xml.dom.minidom.parseString(buffer)
            pretty_xml = dom.toprettyxml(indent="  ", encoding="UTF-8").decode('utf-8')
            
            # Entferne leere Zeilen und XML-Deklaration
            lines = [line for line in pretty_xml.split('\n') if line.strip()]
            if lines and lines[0].startswith('<?xml'):
                lines = lines[1:]  # Entferne XML-Deklaration
            
            pretty_xml = '\n'.join(lines)
        
            self.log_message(f"\n[{timestamp}] ✓ XML empfangen und formatiert:\n\n")
            self.log_message(pretty_xml)
            self.log_message("\n")
        
            # Bestätigung senden
            try:
                response = "<?xml version='1.0' encoding='UTF-8'?><response>OK</response>"
                client_socket.send(response.encode('utf-8'))
            except:
                pass
        
            # Statistik aktualisieren
            self.message_count += 1
            self.update_stats()
        
        except Exception as e:
            self.log_message(f"\n[{timestamp}] ✗ XML-Parsing-Fehler: {e}\n\n")

    def export_to_file(self):
        """
        Exportiert den Inhalt des Textfelds in eine Datei
        """
        try:
            content = self.output_text.get(1.0, tk.END)
            
            if not content.strip():
                messagebox.showwarning("Export", "Keine Daten zum Exportieren vorhanden")
                return
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"xml_log_{timestamp}.txt"
            
            filepath = filedialog.asksaveasfilename(
                defaultextension=".txt",
                initialfile=default_filename,
                filetypes=[
                    ("Text-Dateien", "*.txt"),
                    ("Log-Dateien", "*.log"),
                    ("Alle Dateien", "*.*")
                ],
                title="Export - Speichern unter"
            )
            
            if filepath:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(content)
                
                messagebox.showinfo(
                    "Export erfolgreich", 
                    f"Daten erfolgreich gespeichert:\n\n{filepath}"
                )
                
                if messagebox.askyesno("Datei öffnen?", "Möchten Sie den Export-Ordner öffnen?"):
                    folder = os.path.dirname(filepath)
                    os.startfile(folder)
                
        except Exception as e:
            messagebox.showerror("Export-Fehler", f"Fehler beim Speichern:\n{e}")
    
    def log_message(self, message):
        """Fügt Nachricht zum Textfeld hinzu (thread-safe)"""
        self.root.after(0, self._append_text, message)
    
    def _append_text(self, message):
        """Hilfsmethode zum Hinzufügen von Text"""
        self.output_text.config(state='normal')
        self.output_text.insert(tk.END, message)
        self.output_text.see(tk.END)
        self.output_text.config(state='disabled')
    
    def update_stats(self):
        """Aktualisiert Statistik-Anzeige"""
        self.root.after(0, self._update_stats_label)
    
    def _update_stats_label(self):
        """Hilfsmethode zum Aktualisieren der Statistik"""
        self.stats_label.config(text=f"Empfangene Nachrichten: {self.message_count}")
    
    def clear_output(self):
        """Löscht die Textausgabe"""
        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state='disabled')
    
    def on_closing(self):
        """Wird beim Schließen des Fensters aufgerufen"""
        if self.is_running:
            self.stop_server()
        self.root.destroy()

# Hauptprogramm
if __name__ == "__main__":
    root = tk.Tk()
    app = XMLTCPServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()