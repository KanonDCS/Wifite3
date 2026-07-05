# Wifite 3 — Auditor de Redes Inalámbricas de Alto Rendimiento

Wifite 3 es una rediseño completo y modernizado del auditor original de redes inalámbricas, reconstruido para profesionales de seguridad, pentesters y equipos de seguridad (Red-Teams).

Esta versión (Wifite 3) ha sido desarrollada y es mantenida por **KanonDCS**.

Automatiza el uso de las herramientas existentes de auditoría inalámbrica bajo una interfaz de línea de comandos limpia y automatizada. Se acabó el tener que memorizar argumentos de comandos complejos y secuencias manuales.

---

## ¿Qué hay de nuevo en Wifite 3?

Wifite 3 actualiza la base de código para soportar estándares modernos de cifrado Wi-Fi, optimizaciones de rendimiento y seguridad operativa (OpSec):

1. **Soporte WPA3 y SAE**: Escaneo nativo y captura pasiva de handshakes WPA3/SAE, convirtiendo los paquetes directamente al formato **22000** de hashcat (`.hc22000`) para su descifrado.
2. **Detección de PMF (802.11w)**: Detecta tramas de gestión protegidas (PMF requerido o capaz) de forma dinámica desde los elementos de información RSN. Omite automáticamente los ataques de desautenticación en redes con PMF requerido para mantener el sigilo.
3. **Escaneo Batch de Alta Velocidad**: Arranca un único proceso `tshark` en segundo plano para procesar y enriquecer en tiempo real las capacidades de todos los AP detectados (PMF, WPA3 y suites AKM), eliminando el cuello de botella de abrir un subproceso por cada BSSID.
4. **Validador Criptográfico Scapy**: Reemplaza el antiguo validador de `pyrit` por un framework de análisis EAPOL basado en Scapy para verificar la integridad estructural de los handshakes.
5. **Borrado Seguro Forense (OpSec)**: Añade un motor de limpieza forense que sobreescribe todos los archivos temporales `.cap` y listas de filtrado con bytes aleatorios (3 pasadas) y sincroniza los cambios físicamente (`os.fsync()`) antes de borrarlos.
6. **Interfaz Unicode Moderna**: Se rediseñó la tabla de objetivos usando bordes y conectores Unicode de caja limpia (`┌`, `┬`, `┐`, `│`, `├`, `┼`, `┤`, `└`, `┴`, `┘`) para una salida visual profesional y ordenada.
7. **Soporte Distros PEP 668**: El script de instalación integra la instalación de dependencias de Python directamente mediante los paquetes del sistema de Kali y Parrot OS (`python3-scapy`, `python3-tqdm`, `python3-colorama`).

---

## Ataques Soportados
* **WPA3/SAE**: Captura pasiva del handshake de asociación y descifrado offline (modo 22000).
* **Handshake WPA2/1**: Captura del handshake de 4 vías + descifrado offline.
* **PMKID**: Captura sin clientes de hashes PMKID mediante `hcxdumptool` y conversión a formato 22000.
* **WPS**: Ataque Pixie-Dust offline y ataque de PIN online (a través de `reaver` o `bully`).
* **WEP**: Inyección de tráfico clásica (replay, fragmentación, chop-chop, hirte, caffe-latte).

---

## Sistemas Operativos Soportados
* **Kali Linux** (Recomendado)
* **Parrot OS**
* **Termux / NetHunter** (Entornos Android)

---

## Requisitos

### Tarjeta de Red Inalámbrica
Un adaptador de red que soporte **Modo Monitor** e **Inyección de Paquetes**.

### Herramientas Externas
* Suite `aircrack-ng` (incluye `airmon-ng`, `airodump-ng`, `aireplay-ng`, `aircrack-ng`)
* `iw`
* `tshark` (de Wireshark)
* `hcxdumptool` y `hcxtools` (para PMKID y WPA3)
* `hashcat` (para descifrado offline)
* `reaver` o `bully` (para ataques WPS)

---

## Instalación

### 1. Clonar el repositorio:
```bash
git clone https://github.com/KanonDCS/Wifite3.git
cd wifite3
```

### 2. Instalar dependencias e iniciar:
```bash
chmod +x install.sh
sudo ./install.sh
```

---

## Uso

### Escanear y seleccionar objetivos interactivamente:
```bash
sudo wifite
```

### Atacar solo objetivos WPA/WPA3 y generar un reporte HTML:
```bash
sudo wifite --wpa --report html
```

### Capturar únicamente hashes PMKID:
```bash
sudo wifite --pmkid
```

---

## Créditos
Wifite 3 es desarrollado y modernizado por **KanonDCS** (<kanondcs@proton.me>).
Diseño original por derv82.
Licenciado bajo GNU GPLv2.
