---
tags:
  - python
  - tkinter
  - gui
---
En esta etapa final, daremos los toques finales a nuestro chat multiusuario, centrándonos en la seguridad y privacidad de las conversaciones. Utilizaremos la librería SSL y herramientas como OpenSSL para implementar un cifrado robusto.

Aprenderemos cómo integrar estas tecnologías en nuestro chat para asegurar que las comunicaciones entre usuarios sean seguras y privadas. Esta sesión es crucial para entender la importancia del cifrado en aplicaciones de mensajería y cómo aplicarlo efectivamente en proyectos reales.

A continuación, se proporcionan los comandos utilizados en la clase:

- **openssl genpkey -algorithm RSA -out server-key.key -aes256**

Esta instrucción genera una nueva clave privada RSA. La opción ‘**-algorithm RSA**‘ especifica el uso del algoritmo RSA. ‘**-out server-key.key**‘ indica que la clave generada se guardará en un archivo llamado ‘**server-key.key**‘. La opción ‘**-aes256**‘ significa que la clave privada será cifrada usando el algoritmo AES-256, lo que añade una capa de seguridad al requerir una contraseña para acceder a la clave.

- **openssl req -new -key server-key.key -out server.csr**

Esta línea crea una nueva Solicitud de Firma de Certificado (CSR) utilizando la clave privada RSA que generaste. ‘**-new**‘ indica que se trata de una nueva solicitud, ‘**-key server-key.key**‘ especifica que se usará la clave privada almacenada en ‘**server-key.key**‘, y ‘**-out server.csr**‘ guarda la CSR generada en un archivo llamado ‘**server.csr**‘. La CSR es necesaria para solicitar un certificado digital a una Autoridad Certificadora (CA).

- **openssl x509 -req -days 365 -in server.csr -signkey server-key.key -out server-cert.pem**

Este comando genera un certificado autofirmado basado en la CSR. ‘**-req**‘ indica que se está procesando una CSR, ‘**-days 365**‘ establece la validez del certificado por un año, ‘**-in server.csr**‘ especifica la CSR de entrada, ‘**-signkey server-key.key**‘ utiliza la misma clave privada para firmar el certificado, y ‘**-out server-cert.pem**‘ guarda el certificado generado en un archivo llamado ‘**server-cert.pem**‘.

- **openssl rsa -in server-key.key -out server-key.key**

Este comando se utiliza para quitar la contraseña de una clave privada RSA protegida. ‘**-in server-key.key**‘ especifica el archivo de la clave privada cifrada como entrada, y ‘**-out server-key.key**‘ indica que la clave privada sin cifrar se guardará en el mismo archivo. Al ejecutar este comando, se te pedirá la contraseña actual de la clave privada. Una vez proporcionada, OpenSSL generará una versión sin cifrar de la clave privada y la guardará en el mismo archivo, sobrescribiendo la versión cifrada.

Este paso se hace a menudo para simplificar la automatización en entornos donde ingresar una contraseña manualmente no es práctico. Sin embargo, es importante ser consciente de que al eliminar la contraseña, la clave privada se vuelve más vulnerable al acceso no autorizado.

# Server.py
Deberá estar accesible públicamente para que los clientes se puedan conectar.

```python
#!/usr/bin/env python3
import socket
import threading
import ssl


def client_thread(client_socket, clients, usernames):

	username = client_socket.recv(1024).decode()
	usernames[client_socket] = username
	print(f"\n[+] El usuario {username} se ha conectado al chat")

	for client in clients:
		if client is not client_socket:
			client.sendall(f"\n[+] El usuario {username} ha entrado al chat\n\n".encode())

	while True:
		try:
			message = client_socket.recv(1024).decode()
			
			if not message:
				break
			if message == "!usuarios":
				client_socket.sendall(f"\n[+] Listado de usuarios disponibles: {', '.join(usernames.values())}\n\n".encode())
				continue

			for client in clients:
				if client is not client_socket:
					client.sendall(f"{message}\n".encode())

		except:
			break
			
	client_socket.close()
	clients.remove(client_socket)
	del usernames[client_socket]


def server_program():

	host = 'localhost'
	port = 12345
	
	server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) # time_wait reutilizar el puerto si me desconecto para volverme a conectar.
	server_socket.bind((host, port))
	server_socket = ssl.wrap_socket(server_socket, keyfile="server-key.key", certfile="server-cert.pem", server_side=True) # comunicacion cifrada con clave pribada y certfile
	server_socket.listen()

	print(f"\n[+] El servidor está en escucha de conexiones entrantes...")

	clients = []
	usernames = {}

	while True:
		client_socket, address = server_socket.accept()
		clients.append(client_socket)

		print(f"\n[+] Se ha conectado un nuevo cliente: {address}")
	
		thread = threading.Thread(target=client_thread, args=(client_socket, clients, usernames))
		thread.daemon = True # se pone como en segundo plano de modo que no infiere en la finalización del programa, asi al cerrarse, concluye.
		thread.start()

	sever_socket.close()

if __name__ == '__main__':
	server_program()


```

# Client.py
El cliente tendrá interfaz gráfica.
```python
#!/usr/bin/env python3  
import ssl  
import socket  
import threading  
from tkinter import *  
from tkinter.scrolledtext import ScrolledText  
  
  
def send_message(client_socket, username, text_widget, entry_widget):  
    message = entry_widget.get()  
    client_socket.sendall(f"{username} > {message}".encode())  
  
    entry_widget.delete(0, END)  
    text_widget.configure(state='normal')  
    text_widget.insert(END, f"{username} > {message}\n")  
    text_widget.configure(state='disabled')  
  
  
def recive_message(client_socket, text_widget):  
    while True:  
        try:  
            message = client_socket.recv(1024).decode()  
  
            if not message:  
                break  
  
            text_widget.configure(state='normal')  
            text_widget.insert(END, message)  
            text_widget.configure(state='disabled')  
  
        except:  
            break  
  
  
def list_users_request(client_socket):  
    client_socket.sendall("!usuarios".encode())  
  
  
def exit_request(client_socket, username, window):  
    client_socket.sendall(f"\n[!] El usuario {username} ha abandonado el chat\n".encode())  
    client_socket.close()  
    window.quit()  
    window.destroy()  
  
  
def client_program():  
    host = 'localhost'  
    port = 12345  
  
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
    client_socket = ssl.wrap_socket(client_socket)  
    client_socket.connect((host, port))  
  
    username = input(f"\n[+] Introduce tu usuario: ")  
    client_socket.sendall(username.encode())  
  
    window = Tk()  
    window.title("Chat")  
  
    text_widget = ScrolledText(window, state='disabled')  
    text_widget.pack(padx=5, pady=5)  
  
    # Frame para unificar el boton y el texto  
    frame_widget = Frame(window)  
    frame_widget.pack(padx=5, pady=2, fill=BOTH, expand=1)  
  
    # Entrada de texto  
    entry_widget = Entry(frame_widget, font=("Arial", 14))  
    entry_widget.bind("<Return>", lambda _: send_message(client_socket, username, text_widget, entry_widget))  
    entry_widget.pack(side=LEFT, fill=X, expand=1)  
  
    # Boton de envio  
    button_widget = Button(frame_widget, text="Enviar",  
                           command=lambda: send_message(client_socket, username, text_widget, entry_widget))  
    button_widget.pack(side=RIGHT, padx=5)  
  
    # Frame para unificar el boton de Usuarios y el de Salida  
  
  
    frame2_widget = Frame(window)  
    frame2_widget.pack(padx=5, pady=2, fill=BOTH, expand=1)  
      
    # Boton de Usuarios  
    users_widget = Button(frame2_widget, text="Listar Usuarios", command=lambda: list_users_request(client_socket))  
    users_widget.pack(side=LEFT, fill=X, expand=1)  
      
    # Boton de Salida  
    exit_widget = Button(frame2_widget, text="Salir", command=lambda: exit_request(client_socket, username, window))  
    exit_widget.pack(side=RIGHT, padx=5)  
      
    # hilos  
    thread = threading.Thread(target=recive_message, args=(client_socket, text_widget))  
    thread.daemon = True  
    thread.start()  
      
    window.mainloop()  
    client_socket.close()  


if __name__ == '__main__':  
	client_program()
```

## Copia cliente seguridad
```python
#!/usr/bin/env python3
import socket
import threading
from tkinter import *
from tkinter.scrolledtext import ScrolledText


def send_message(client_socket, username, text_widget, entry_widget):
	message = entry_widget.get()
	client_socket.sendall(f"{username} > {message}".encode())
	
	entry_widget.delete(0, END)
	text_widget.configure(state='normal')
	text_widget.insert(END, f"{username} > {message}\n")
	text_widget.configure(state='disabled')


def recive_message(client_socket, text_widget):
	while True:
		try:
			message = client_socket.recv(1024).decode()

			if not message:
				break
			
			text_widget.configure(state='normal')
			text_widget.insert(END, message)
			text_widget.configure(state='disabled')
			
		except:
			break


def list_users_request(client_socket):
	client_socket.sendall("!usuarios".encode())


def exit_request(client_socket, username, window):
	client_socket.sendall(f"\n[!] El usuario {username} ha abandonado el chat\n".encode())
	client_socket.close()
	window.quit()
	window.destroy()


def client_program():
	host = 'localhost'
	port = 12345

	client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	client_socket.connect((host, port))

	username = input(f"\n[+] Introduce tu usuario: ")
	client_socket.sendall(username.encode())

	window = Tk()
	window.title("Chat")

	text_widget = ScrolledText(window, state='disabled')
	text_widget.pack(padx=5, pady=5)

	# Frame para unificar el boton y el texto
	frame_widget = Frame(window)
	frame_widget.pack(padx=5, pady=2, fill=BOTH, expand=1)

	# Entrada de texto
	entry_widget = Entry(frame_widget, font=("Arial", 14))
	entry_widget.bind("<Return>", lambda _: send_message(client_socket, username, text_widget, entry_widget))
	entry_widget.pack(side=LEFT,  fill=X, expand=1)
	
	
	# Boton de envio
	button_widget = Button(frame_widget, text="Enviar", command=lambda: send_message(client_socket, username, text_widget, entry_widget))
	button_widget.pack(side=RIGHT, padx=5)
	'''
	# Boton de Usuarios
	users_widget = Button(window, text="Listar Usuarios", command=lambda: list_users_request(client_socket))
	users_widget.pack(padx=5, pady=5, expand=1)

	# Boton de Salida
	exit_widget = Button(window, text="Salir", command=lambda: exit_request(client_socket, username, window))
	exit_widget.pack(padx=5, pady=5, expand=1)
	'''
	################ Prueba 1####################################################################################
	# Frame para unificar el boton de Usuarios y el de Salida
    frame2_widget = Frame(window)
    frame2_widget.pack(padx=5, pady=2, fill=BOTH, expand=1)

    # Boton de Usuarios
    users_widget = Button(frame2_widget, text="Listar Usuarios", command=lambda: list_users_request(client_socket))
    users_widget.pack(side=LEFT, fill=X, expand=1)

    # Boton de Salida
    exit_widget = Button(frame2_widget, text="Salir", command=lambda: exit_request(client_socket, username, window))
    exit_widget.pack(side=RIGHT, padx=5)
	###############################################################################################################

	# hilos
	thread = threading.Thread(target=recive_message, args=(client_socket, text_widget))
	thread.daemon = True
	thread.start()

	window.mainloop()
	client_socket.close()


if __name__ == '__main__':
	client_program()

```