# -*- coding: utf-8 -*-
import urllib2
import urllib

urlCompleta = raw_input("Introduce url a escanear: ")			#url a escanear

with open("xss", "r") as archivo:				#Se recorre el archivo xss añadiendo el codigo a la url
	for linea in archivo:					#Se lee linea a linea
		codificada = urllib.quote_plus(linea[:-1])	#Codificamos el codigo xss a formato de url
		urlDefinitiva = ''				#Creamos la url denifitiva modificada
		urlDefinitiva = urlCompleta + codificada	#Añadimos el codigo que comprueba si es explotable a la url
		req = urllib2.Request(urlDefinitiva)		#Lanzamos la peticion al servidor
		req.add_header('User-agent', 'Mozilla 5.10')	#He tenido que añadir el agent ya que algunos sitios mostraban error 400
		res = urllib2.urlopen(req)			#Recuperamos el contenido de la web
		html = res.read()				#Pasamos el contenido a texto
		if linea[:-1] in html:				#Comprobamos si el codigo a sido injectado en la web
			print  ('\033[31m' + "Posible XSS" + '\033[0m') 	#Mostramos un aviso en rojo de posible xss
			print(urlDefinitiva)				#Se muestra la url resultante en caso de poder ser explotable
