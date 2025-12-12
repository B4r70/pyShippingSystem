""" 
//----------------------------------------------------------------------------------/
// # pyShippingSystem                                                               /
// ---------------------------------------------------------------------------------/
// Abschnitt . . : Communication Tools                                              /
// Datei . . . . : pyShippingSystem.py                                              /
// Autor . . . . : Bartosz Stryjewski                                               /
// Erstellt am . : 10.12.2025                                                       /
// Beschreibung  : Tool empfängt XML und generiert Versandeinheitennummern          /
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
import json
import time

class ConfigDialog:
    """Konfigurationsmenü für pyShippingSystem"""
    
    def __init__(self, parent, config):
        self.result = None
        self.config = config.copy()
        
        # Dialog-Fenster erstellen
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Konfiguration")
        self.dialog.geometry("800x600")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        self.create_widgets()
        self.load_config()
        
    def create_widgets(self):
        """Erstellt die Dialog-Elemente"""
        
        # Notebook für Tabs
        notebook = ttk.Notebook(self.dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Tab 1: Allgemeine Einstellungen
        general_frame = ttk.Frame(notebook)
        notebook.add(general_frame, text="Allgemein")
        
        # Server-Einstellungen
        ttk.Label(general_frame, text="Server-Port:", font=('Arial', 10, 'bold')).grid(row=0, column=0, sticky='w', padx=10, pady=10)
        self.port_var = tk.StringVar()
        ttk.Entry(general_frame, textvariable=self.port_var, width=20).grid(row=0, column=1, sticky='w', padx=10, pady=10)
        
        ttk.Label(general_frame, text="Antwort-Verzögerung (Sekunden):", font=('Arial', 10, 'bold')).grid(row=1, column=0, sticky='w', padx=10, pady=10)
        self.delay_var = tk.StringVar()
        ttk.Entry(general_frame, textvariable=self.delay_var, width=20).grid(row=1, column=1, sticky='w', padx=10, pady=10)
        
        # Verzeichnisse
        ttk.Label(general_frame, text="Eingehende XML:", font=('Arial', 10, 'bold')).grid(row=2, column=0, sticky='w', padx=10, pady=10)
        self.incoming_var = tk.StringVar()
        ttk.Entry(general_frame, textvariable=self.incoming_var, width=40).grid(row=2, column=1, sticky='w', padx=10, pady=10)
        ttk.Button(general_frame, text="...", command=lambda: self.browse_folder(self.incoming_var), width=5).grid(row=2, column=2, padx=5)
        
        ttk.Label(general_frame, text="Ausgehende XML:", font=('Arial', 10, 'bold')).grid(row=3, column=0, sticky='w', padx=10, pady=10)
        self.outgoing_var = tk.StringVar()
        ttk.Entry(general_frame, textvariable=self.outgoing_var, width=40).grid(row=3, column=1, sticky='w', padx=10, pady=10)
        ttk.Button(general_frame, text="...", command=lambda: self.browse_folder(self.outgoing_var), width=5).grid(row=3, column=2, padx=5)
        
        # Tab 2: Versandarten / Nummernkreise
        shipping_frame = ttk.Frame(notebook)
        notebook.add(shipping_frame, text="Versandarten")
        
        # Treeview für Versandarten
        columns = ('versandart', 'prefix', 'start', 'end', 'current')
        self.tree = ttk.Treeview(shipping_frame, columns=columns, show='headings', height=15)
        
        self.tree.heading('versandart', text='Versandart')
        self.tree.heading('prefix', text='Präfix')
        self.tree.heading('start', text='Start')
        self.tree.heading('end', text='Ende')
        self.tree.heading('current', text='Aktuell')
        
        self.tree.column('versandart', width=100)
        self.tree.column('prefix', width=80)
        self.tree.column('start', width=120)
        self.tree.column('end', width=120)
        self.tree.column('current', width=120)
        
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Buttons für Versandarten
        button_frame = ttk.Frame(shipping_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(button_frame, text="Hinzufügen", command=self.add_shipping_type).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Bearbeiten", command=self.edit_shipping_type).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Löschen", command=self.delete_shipping_type).pack(side=tk.LEFT, padx=5)
        
        # Buttons unten
        bottom_frame = ttk.Frame(self.dialog)
        bottom_frame.pack(fill=tk.X, padx=10, pady=10)
        
        ttk.Button(bottom_frame, text="Speichern", command=self.save_config).pack(side=tk.RIGHT, padx=5)
        ttk.Button(bottom_frame, text="Abbrechen", command=self.dialog.destroy).pack(side=tk.RIGHT, padx=5)
        
    def browse_folder(self, var):
        """Ordner-Auswahl-Dialog"""
        folder = filedialog.askdirectory()
        if folder:
            var.set(folder)
    
    def load_config(self):
        """Lädt Konfiguration in Dialog"""
        self.port_var.set(str(self.config.get('server', {}).get('port', 8888)))
        self.delay_var.set(str(self.config.get('server', {}).get('response_delay_seconds', 0.5)))
        self.incoming_var.set(self.config.get('directories', {}).get('incoming_xml', ''))
        self.outgoing_var.set(self.config.get('directories', {}).get('outgoing_xml', ''))
        
        # Lade Versandarten
        for code, data in self.config.get('shipping_types', {}).items():
            self.tree.insert('', 'end', values=(
                code,
                data.get('prefix', 'PYSS'),
                data.get('start', 0),
                data.get('end', 99999999999),
                data.get('current', 0)
            ))
    
    def add_shipping_type(self):
        """Fügt neue Versandart hinzu"""
        dialog = ShippingTypeDialog(self.dialog, "Neue Versandart")
        if dialog.result:
            self.tree.insert('', 'end', values=dialog.result)
    
    def edit_shipping_type(self):
        """Bearbeitet Versandart"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warnung", "Bitte eine Versandart auswählen")
            return
        
        item = self.tree.item(selection[0])
        values = item['values']
        
        dialog = ShippingTypeDialog(self.dialog, "Versandart bearbeiten", values)
        if dialog.result:
            self.tree.item(selection[0], values=dialog.result)
    
    def delete_shipping_type(self):
        """Löscht Versandart"""
        selection = self.tree.selection()
        if not selection:
            messagebox.showwarning("Warnung", "Bitte eine Versandart auswählen")
            return
        
        if messagebox.askyesno("Bestätigung", "Versandart wirklich löschen?"):
            self.tree.delete(selection[0])
    
    def save_config(self):
        """Speichert Konfiguration"""
        try:
            # Validierung
            port = int(self.port_var.get())
            delay = float(self.delay_var.get())
            
            if port < 1 or port > 65535:
                raise ValueError("Port muss zwischen 1 und 65535 liegen")
            
            # Baue Config-Dictionary
            self.config = {
                'server': {
                    'port': port,
                    'response_delay_seconds': delay
                },
                'directories': {
                    'incoming_xml': self.incoming_var.get(),
                    'outgoing_xml': self.outgoing_var.get()
                },
                'shipping_types': {}
            }
            
            # Sammle Versandarten
            for item in self.tree.get_children():
                values = self.tree.item(item)['values']
                code = values[0]
                self.config['shipping_types'][code] = {
                    'prefix': values[1],
                    'start': int(values[2]),
                    'end': int(values[3]),
                    'current': int(values[4])
                }
            
            self.result = self.config
            self.dialog.destroy()
            
        except ValueError as e:
            messagebox.showerror("Fehler", f"Ungültige Eingabe: {e}")

class ShippingTypeDialog:
    """Dialog zum Hinzufügen/Bearbeiten von Versandarten"""
    
    def __init__(self, parent, title, values=None):
        self.result = None
        
        self.dialog = tk.Toplevel(parent)
        self.dialog.title(title)
        self.dialog.geometry("400x300")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        
        # Eingabefelder
        ttk.Label(self.dialog, text="Versandart-Code:").grid(row=0, column=0, sticky='w', padx=10, pady=10)
        self.code_var = tk.StringVar(value=values[0] if values else '')
        ttk.Entry(self.dialog, textvariable=self.code_var, width=30).grid(row=0, column=1, padx=10, pady=10)
        
        ttk.Label(self.dialog, text="Präfix:").grid(row=1, column=0, sticky='w', padx=10, pady=10)
        self.prefix_var = tk.StringVar(value=values[1] if values else 'PYSS')
        ttk.Entry(self.dialog, textvariable=self.prefix_var, width=30).grid(row=1, column=1, padx=10, pady=10)
        
        ttk.Label(self.dialog, text="Start:").grid(row=2, column=0, sticky='w', padx=10, pady=10)
        self.start_var = tk.StringVar(value=values[2] if values else '10000000000')
        ttk.Entry(self.dialog, textvariable=self.start_var, width=30).grid(row=2, column=1, padx=10, pady=10)
        
        ttk.Label(self.dialog, text="Ende:").grid(row=3, column=0, sticky='w', padx=10, pady=10)
        self.end_var = tk.StringVar(value=values[3] if values else '19999999999')
        ttk.Entry(self.dialog, textvariable=self.end_var, width=30).grid(row=3, column=1, padx=10, pady=10)
        
        ttk.Label(self.dialog, text="Aktuell:").grid(row=4, column=0, sticky='w', padx=10, pady=10)
        self.current_var = tk.StringVar(value=values[4] if values else '10000000000')
        ttk.Entry(self.dialog, textvariable=self.current_var, width=30).grid(row=4, column=1, padx=10, pady=10)
        
        # Buttons
        button_frame = ttk.Frame(self.dialog)
        button_frame.grid(row=5, column=0, columnspan=2, pady=20)
        
        ttk.Button(button_frame, text="OK", command=self.ok_clicked).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Abbrechen", command=self.dialog.destroy).pack(side=tk.LEFT, padx=5)
    
    def ok_clicked(self):
        """Validiert und speichert Eingabe"""
        try:
            code = self.code_var.get().strip()
            prefix = self.prefix_var.get().strip()
            start = int(self.start_var.get())
            end = int(self.end_var.get())
            current = int(self.current_var.get())
            
            if not code or len(code) > 4:
                raise ValueError("Versandart-Code muss 1-4 Zeichen haben")
            
            if start >= end:
                raise ValueError("Start muss kleiner als Ende sein")
            
            if current < start or current > end:
                raise ValueError("Aktuell muss zwischen Start und Ende liegen")
            
            self.result = (code, prefix, start, end, current)
            self.dialog.destroy()
            
        except ValueError as e:
            messagebox.showerror("Fehler", f"Ungültige Eingabe: {e}")

class XMLTCPServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("pyShippingSystem")
        self.root.geometry("900x700")
        
        self.server_socket = None
        self.server_thread = None
        self.is_running = False
        self.config = {}
        self.config_file = "pyShippingSystem_config.json"
        
        # Lade oder erstelle Konfiguration
        self.load_config()
        
        self.create_widgets()
        
    def create_widgets(self):
        """Erstellt die GUI-Elemente"""
        
        # Header Frame
        header_frame = ttk.Frame(self.root, padding="10")
        header_frame.pack(fill=tk.X)
        
        # Port-Eingabe
        ttk.Label(header_frame, text="Port:", font=('Arial', 10)).pack(side=tk.LEFT, padx=5)
        
        self.port_entry = ttk.Entry(header_frame, width=10, font=('Arial', 10))
        self.port_entry.insert(0, str(self.config.get('server', {}).get('port', 8888)))
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
        
        # Konfiguration Button
        self.config_button = ttk.Button(
            header_frame,
            text="⚙ Konfiguration",
            command=self.open_config_dialog,
            width=15
        )
        self.config_button.pack(side=tk.RIGHT, padx=5)
        
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
        
        ttk.Label(output_frame, text="Log:", font=('Arial', 10, 'bold')).pack(anchor=tk.W)
        
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
            text="Empfangene Nachrichten: 0 | Versendete Nachrichten: 0",
            font=('Arial', 9)
        )
        self.stats_label.pack(side=tk.LEFT)
        
        self.message_count_in = 0
        self.message_count_out = 0
        
    def load_config(self):
        """Lädt Konfiguration aus JSON-Datei"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
            else:
                # Standard-Konfiguration
                self.config = {
                    'server': {
                        'port': 8888,
                        'response_delay_seconds': 0.5
                    },
                    'directories': {
                        'incoming_xml': './incoming',
                        'outgoing_xml': './outgoing'
                    },
                    'shipping_types': {
                        'GN01': {
                            'prefix': 'PYSS',
                            'start': 10000000000,
                            'end': 19999999999,
                            'current': 10000000000
                        },
                        'SN01': {
                            'prefix': 'PYSS',
                            'start': 20000000000,
                            'end': 29999999999,
                            'current': 20000000000
                        },
                        'IMP': {
                            'prefix': 'PYSS',
                            'start': 30000000000,
                            'end': 39999999999,
                            'current': 30000000000
                        }
                    }
                }
                self.save_config()
        except Exception as e:
            messagebox.showerror("Fehler", f"Fehler beim Laden der Konfiguration:\n{e}")
    
    def save_config(self):
        """Speichert Konfiguration in JSON-Datei"""
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2, ensure_ascii=False)
        except Exception as e:
            messagebox.showerror("Fehler", f"Fehler beim Speichern der Konfiguration:\n{e}")
    
    def open_config_dialog(self):
        """Öffnet Konfigurationsdialog"""
        dialog = ConfigDialog(self.root, self.config)
        self.root.wait_window(dialog.dialog)
        
        if dialog.result:
            self.config = dialog.result
            self.save_config()
            self.port_entry.delete(0, tk.END)
            self.port_entry.insert(0, str(self.config['server']['port']))
            messagebox.showinfo("Erfolg", "Konfiguration gespeichert!")
    
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
            
            # Erstelle Verzeichnisse falls nicht vorhanden
            os.makedirs(self.config['directories']['incoming_xml'], exist_ok=True)
            os.makedirs(self.config['directories']['outgoing_xml'], exist_ok=True)
            
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

        # Server-Socket herunterfahren und schließen
        if self.server_socket:
            try:
                # Versucht, laufende accept()/recv() sauber zu beenden
                self.server_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                # Kann passieren, wenn der Socket schon zu ist – ist ok
                pass
            except Exception as e:
                self.log_message(f"Fehler bei shutdown: {e}\n")

            try:
                self.server_socket.close()
            except Exception as e:
                self.log_message(f"Fehler beim Schließen des Server-Sockets: {e}\n")

            self.server_socket = None

        # 🔽 HIER kommt dein Thread-Join-Block hin 🔽
        if self.server_thread and self.server_thread.is_alive():
            try:
                self.server_thread.join(timeout=1.0)
            except Exception as e:
                self.log_message(f"Fehler beim Warten auf Server-Thread: {e}\n")
        self.server_thread = None
        # 🔼 bis hierhin 🔼

        # GUI aktualisieren
        self.bind_button.config(text="Bind")
        self.status_label.config(text="● Gestoppt", foreground="red")
        self.port_entry.config(state='normal')

        self.log_message("Server gestoppt\n")
    
    def run_server(self):
        """Server-Loop für eingehende Verbindungen"""
        self.log_message("Server-Thread gestartet, warte auf Verbindungen...\n")
        # Timeout EINMAL setzen, nicht in jeder Runde
        self.server_socket.settimeout(1.0)

        while self.is_running:
            try:
                client_socket, client_address = self.server_socket.accept()

                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address),
                    daemon=True
                )
                client_thread.start()

            except socket.timeout:
                # einfach weiter pollen
                continue

            except OSError as e:
                # Typischer Fall: Socket wurde während accept() geschlossen,
                # z.B. durch stop_server()
                if not self.is_running:
                    # sauberer Shutdown, kein echter Fehler
                    break
                self.log_message(f"Server-OSError in run_server: {e}\n")
                # hier KANNST du auch continue statt break machen, wenn du
                # z.B. beim nächsten Loop wieder lauschen willst
                break

            except Exception as e:
                self.log_message(f"Unerwarteter Server-Fehler in run_server: {e}\n")
                import traceback
                self.log_message(traceback.format_exc())
                break

        self.log_message("Server-Thread beendet.\n")

    
    def handle_client(self, client_socket, client_address):
        """Verarbeitet einzelne Client-Verbindung"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_message(f"\n{'='*70}\n")
        self.log_message(f"[{timestamp}] Neue Verbindung von {client_address[0]}:{client_address[1]}\n")
        self.log_message(f"{'='*70}\n")
        
        buffer = ""
        last_data_time = datetime.now()
        chunk_counter = 0
        no_data_timeout = 60
        
        try:
            client_socket.settimeout(1.0)
            
            while self.is_running:
                try:
                    chunk = client_socket.recv(4096)
                    
                    if not chunk:
                        self.log_message(f"[{datetime.now().strftime('%H:%M:%S')}] Client hat Verbindung geschlossen\n")
                        break
                    
                    chunk_counter += 1
                    chunk_str = chunk.decode('utf-8', errors='replace')
                    
                    self.log_message(f"\n--- CHUNK #{chunk_counter} ---\n")
                    self.log_raw_data(chunk_str, "IN")
                    
                    buffer += chunk_str
                    last_data_time = datetime.now()
                    
                    self.log_message(f"Buffer-Größe: {len(buffer)} Zeichen\n")
                    
                    # Prüfe auf mehrere Telegramme im Buffer (getrennt durch ETX)
                    while chr(0x03) in buffer:
                        etx_pos = buffer.find(chr(0x03))
                        telegram = buffer[:etx_pos + 1]  # Inkl. ETX
                        buffer = buffer[etx_pos + 1:]  # Rest für nächstes Telegramm
                        
                        # Prüfe ob KEEPALIVE
                        if 'KEEPALIVE' in telegram:
                            self.log_message(f"[{datetime.now().strftime('%H:%M:%S')}] ✓ KEEPALIVE empfangen - Sende Bestätigung\n")
                            try:
                                # Sende KEEPALIVE zurück
                                keepalive_response = f"{chr(0x02)}       KEEPALIVE{chr(0x03)}"
                                client_socket.send(keepalive_response.encode('utf-8'))
                                self.log_message(f"[{datetime.now().strftime('%H:%M:%S')}] → KEEPALIVE gesendet\n")
                            except:
                                pass
                        else:
                            # Normales XML-Telegramm
                            self.log_message(f"[{datetime.now().strftime('%H:%M:%S')}] Verarbeite Telegramm ({len(telegram)} Zeichen)...\n")
                            self.process_buffer(telegram, client_socket)
                        
                        last_data_time = datetime.now()
                        chunk_counter = 0
                    
                except socket.timeout:
                    time_since_last_data = (datetime.now() - last_data_time).total_seconds()
                    
                    # Timeout: Verbindung schließen wenn zu lange keine Daten
                    if time_since_last_data >= no_data_timeout:
                        self.log_message(f"[{datetime.now().strftime('%H:%M:%S')}] Timeout nach {no_data_timeout}s - Schließe Verbindung\n")
                        break
                    
                    continue
                        
        except Exception as e:
            self.log_message(f"Fehler: {e}\n")
            import traceback
            self.log_message(f"Traceback:\n{traceback.format_exc()}\n")
        finally:
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
            # PROTOKOLL-PARSING: Erkenne STX + Länge + XML + ETX
            # Format: STX (1 Byte) + Länge (4 Bytes) + XML-Daten + ETX (1 Byte)
            
            original_length = len(buffer)
            self.log_message(f"\n[{timestamp}] === PROTOKOLL-ANALYSE ===\n")
            self.log_message(f"Original Buffer-Länge: {original_length} Zeichen\n")
            self.log_message(f"Erste 10 Zeichen (repr): {repr(buffer[:10])}\n")
            self.log_message(f"Letzte 10 Zeichen (repr): {repr(buffer[-10:])}\n")
            
            # Entferne STX am Anfang (0x02)
            if buffer and ord(buffer[0]) == 0x02:
                self.log_message(f"✓ STX (0x02) gefunden und entfernt\n")
                buffer = buffer[1:]
            
            # Extrahiere Längenangabe (Bytes 2-5, jetzt 1-4)
            if len(buffer) >= 4:
                length_str = buffer[0:4].strip()
                self.log_message(f"Längenangabe (Bytes 2-5): '{length_str}'\n")
                
                if length_str.isdigit():
                    expected_length = int(length_str)
                    self.log_message(f"✓ Erwartete Länge: {expected_length} Zeichen\n")
                    buffer = buffer[4:]  # Entferne Längenangabe
                else:
                    self.log_message(f"⚠ Längenangabe nicht numerisch!\n")
            
            # Entferne ETX am Ende (0x03)
            if buffer and ord(buffer[-1]) == 0x03:
                self.log_message(f"✓ ETX (0x03) gefunden und entfernt\n")
                buffer = buffer[:-1]
            
            # Entferne führende Leerzeichen nach Längenangabe
            buffer = buffer.lstrip()
            
            self.log_message(f"Bereinigte Buffer-Länge: {len(buffer)} Zeichen\n")
            self.log_message(f"Startet mit: {repr(buffer[:50])}\n")
            self.log_message(f"=============================\n\n")

            # Entferne BOM (Byte Order Mark) falls vorhanden
            if buffer.startswith('\ufeff'):
                buffer = buffer[1:]

            # Suche nach <?xml
            xml_start = buffer.find('<?xml')
            if xml_start > 0:
                self.log_message(f"⚠ Fand <?xml an Position {xml_start}, schneide davor ab\n")
                buffer = buffer[xml_start:]
            elif xml_start == -1:
                self.log_message(f"\n[{timestamp}] ✗ Kein <?xml gefunden im Buffer\n\n")
                return
        
            # WICHTIG: Ersetze \r durch \n für korrektes XML-Parsing
            buffer = buffer.replace('\r', '\n')
            
            # WICHTIG: Schneide alles NACH </LFS> ab!
            lfs_end = buffer.find('</LFS>')
            if lfs_end != -1:
                buffer = buffer[:lfs_end + 6]
        
            # XML parsen
            root = ET.fromstring(buffer)
            
            # Extrahiere relevante Felder
            phvssnd = root.find('PHVSSND')
            if phvssnd is None:
                self.log_message(f"\n[{timestamp}] ERROR#2: Fehlende Daten in der XML. Empfang nicht möglich\n\n")
                return
            
            hcanr1 = phvssnd.find('HCANR1')
            hcpknr = phvssnd.find('HCPKNR_NUM')
            hcvavs = phvssnd.find('HCVAVS')
            
            if hcanr1 is None or hcpknr is None or hcvavs is None:
                self.log_message(f"\n[{timestamp}] ERROR#2: Fehlende Daten in der XML. Empfang nicht möglich\n\n")
                return
            
            auftragsnr = hcanr1.text
            packstknr = hcpknr.text
            versandart = hcvavs.text
            
            # Prüfe ob Versandart konfiguriert ist
            shipping_config = self.config.get('shipping_types', {}).get(versandart)
            if not shipping_config:
                self.log_message(f"\n[{timestamp}] ERROR#1: Versandart '{versandart}' ist nicht bekannt\n\n")
                return
            
            # Generiere VE-Nummer
            ve_nummer = self.generate_ve_nummer(versandart)
            
            # XML für Anzeige formatieren
            dom = xml.dom.minidom.parseString(buffer)
            pretty_xml = dom.toprettyxml(indent="  ", encoding="UTF-8").decode('utf-8')
            lines = [line for line in pretty_xml.split('\n') if line.strip()]
            if lines and lines[0].startswith('<?xml'):
                lines = lines[1:]
            pretty_xml = '\n'.join(lines)
            
            self.log_message(f"\n[{timestamp}] ✓ XML empfangen:\n\n")
            self.log_message(pretty_xml)
            self.log_message(f"\n\nGenerierte VE-Nummer: {ve_nummer}\n")
            
            # Speichere eingehende XML
            self.save_xml(buffer, auftragsnr, packstknr, 'incoming')
            
            # Statistik aktualisieren
            self.message_count_in += 1
            self.update_stats()
            
            # Erstelle Antwort-XML
            response_xml = self.create_response_xml(root, ve_nummer)
            
            # Verzögerung
            delay = self.config.get('server', {}).get('response_delay_seconds', 0.5)
            time.sleep(delay)
            
            # WICHTIG: Sende Antwort MIT Protokoll-Header!
            response_with_protocol = self.add_protocol_header(response_xml)
            client_socket.send(response_with_protocol.encode('utf-8'))
            
            # Speichere ausgehende XML (ohne Protokoll-Header)
            self.save_xml(response_xml, auftragsnr, packstknr, 'outgoing')
            
            self.log_message(f"[{timestamp}] → Antwort gesendet (mit Protokoll-Header)\n")
            
            # Statistik aktualisieren
            self.message_count_out += 1
            self.update_stats()

        except Exception as e:
            import traceback
            self.log_message(f"\n[{timestamp}] ✗ Fehler: {e}\n")
            self.log_message(f"Traceback:\n{traceback.format_exc()}\n\n")
    
    def add_protocol_header(self, xml_string):
        """Fügt Protokoll-Header hinzu: STX + Länge + XML + ETX"""
        # Berechne Länge (ohne STX und ETX)
        xml_length = len(xml_string)
        length_str = f"{xml_length:04d}"  # 4-stellig, mit führenden Nullen
        
        # Baue kompletten String
        stx = chr(0x02)
        etx = chr(0x03)
        
        protocol_string = f"{stx}{length_str}{xml_string}{etx}"
        
        self.log_message(f"Protokoll-Header: STX + '{length_str}' + XML ({xml_length} Zeichen) + ETX\n")
        
        return protocol_string
    
    def generate_ve_nummer(self, versandart):
        """Generiert VE-Nummer und inkrementiert Zähler"""
        shipping_config = self.config['shipping_types'][versandart]
        
        current = shipping_config['current']
        prefix = shipping_config['prefix']
        end = shipping_config['end']
        
        # Generiere Nummer
        ve_nummer = f"{prefix}{current}"
        
        # Inkrementiere
        current += 1
        if current > end:
            current = shipping_config['start']
        
        # Speichere neue aktuelle Nummer
        self.config['shipping_types'][versandart]['current'] = current
        self.save_config()
        
        return ve_nummer
    
    def create_response_xml(self, root, ve_nummer):
        """Erstellt Antwort-XML mit PHVSRCV"""
        # Kopiere root
        new_root = ET.Element('LFS')
        phvsrcv = ET.SubElement(new_root, 'PHVSRCV')
        
        # Kopiere alle Felder von PHVSSND
        phvssnd = root.find('PHVSSND')
        for child in phvssnd:
            new_child = ET.SubElement(phvsrcv, child.tag)
            new_child.text = child.text
            
            # Füge HCVENR nach HCPKNR ein
            if child.tag == 'HCPKNR_NUM':
                hcvenr = ET.SubElement(phvsrcv, 'HCVENR')
                hcvenr.text = ve_nummer
        
        # Konvertiere zu String
        xml_str = ET.tostring(new_root, encoding='unicode')
        
        # Füge XML-Deklaration hinzu
        xml_str = '<?xml version="1.0" encoding="UTF-8"?>\n' + xml_str
        
        return xml_str
    
    def save_xml(self, xml_content, auftragsnr, packstknr, direction):
        """Speichert XML-Datei"""
        try:
            # Bereinige Dateinamen
            auftragsnr = re.sub(r'[^\w\-_.]', '_', auftragsnr)
            packstknr = re.sub(r'[^\w\-_.]', '_', packstknr)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            filename = f"{auftragsnr}_{packstknr}_{timestamp}.xml"
            
            if direction == 'incoming':
                filepath = os.path.join(self.config['directories']['incoming_xml'], filename)
            else:
                filepath = os.path.join(self.config['directories']['outgoing_xml'], filename)
            
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(xml_content)
                
        except Exception as e:
            self.log_message(f"Fehler beim Speichern: {e}\n")
    
    def export_to_file(self):
        """Exportiert Log in Datei"""
        try:
            content = self.output_text.get(1.0, tk.END)
            
            if not content.strip():
                messagebox.showwarning("Export", "Keine Daten zum Exportieren vorhanden")
                return
            
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            default_filename = f"log_{timestamp}.txt"
            
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
                
                messagebox.showinfo("Export erfolgreich", f"Log gespeichert:\n\n{filepath}")
                
        except Exception as e:
            messagebox.showerror("Export-Fehler", f"Fehler beim Speichern:\n{e}")
    
    def log_message(self, message):
        """Fügt Nachricht zum Log hinzu (thread-safe)"""
        self.root.after(0, self._append_text, message)
        
    def log_raw_data(self, data, direction="IN"):
        """Loggt rohe Daten mit HEX-Dump"""
        timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]  # Millisekunden
        
        # ASCII-Darstellung
        ascii_repr = repr(data)
        
        # HEX-Dump (begrenzt auf 100 Zeichen)
        try:
            hex_dump = ' '.join(f'{ord(c):02x}' for c in data[:50])  # Erste 50 Zeichen
            if len(data) > 50:
                hex_dump += '...'
        except:
            hex_dump = "N/A"
        
        # Länge
        length = len(data)
        
        self.log_message(f"[{timestamp}] {direction} | {length} Bytes\n")
        self.log_message(f"           HEX: {hex_dump}\n")
        self.log_message(f"           ASCII: {ascii_repr[:200]}{'...' if len(ascii_repr) > 200 else ''}\n")
    
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
        self.stats_label.config(
            text=f"Empfangene Nachrichten: {self.message_count_in} | Versendete Nachrichten: {self.message_count_out}"
        )
    
    def clear_output(self):
        """Löscht Log"""
        self.output_text.config(state='normal')
        self.output_text.delete(1.0, tk.END)
        self.output_text.config(state='disabled')
    
    def on_closing(self):
        """Wird beim Schließen aufgerufen"""
        if self.is_running:
            self.stop_server()
        self.root.destroy()

# Hauptprogramm
if __name__ == "__main__":
    root = tk.Tk()
    app = XMLTCPServerGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()