from bs4 import BeautifulSoup, SoupStrainer
import requests
import urllib.parse
import urllib.request
import urllib

def comprobarPagina(pagina, linea):
	req = urllib.request.Request(pagina,data=None,headers={'User-Agent': 'Mozilla 5.10'})
	res = urllib.request.urlopen(req)
	html = str(res.read())                          #Pasamos el contenido a texto
	if linea in html:	                        #Comprobamos si el codigo a sido injectado en la web
        	print  ('\033[31m' + "Posible XSS" + '\033[0m')         #Mostramos un aviso en rojo de posib$
        	print(pagina)


url= input("Introduce url a escanear sin http://: ")
urlCompleta = "http://" + url	#formato completo de url

page = requests.get(urlCompleta) #Se realiza conexion a la pagina indicada
data = page.text		#Se convierte a texto
soup = BeautifulSoup(data, "html.parser")

for link in soup.find_all('a'):	#Se buscan todos los enlaces de la web
	#if url in str(link.get('href')):	#Se utiliza para buscar solo enlaces al propio dominio, para evitar ser intrusivo en paginas externas enlazadas
	if "=" in str(link.get('href')):	#Se busca solo las url que contengan informacion modificable en la url
		urlRevisar = link.get('href')	#Se obtiene el link que contiene informacion modificable
		consulta = urllib.parse.parse_qs(urlRevisar)	#Se trocea la url en el nombre de los valores y sus valores
		variables = list(consulta)			#Se obtiene el listado de valores
		infoVariable = list(consulta.values())		#Se obtiene el listado de nombre de las variables
		with open("xss", "r") as archivo:		#Se recorre el archivo xss donde se encuentra en cada linea un codigo para comprobar si es vulnerable a xss
			for linea in archivo:
				codificada = urllib.parse.quote(linea[:-1])     #Codificamos el codigo xss a formato de url
				urlDefinitiva = ''				#Creamos la url denifitiva modificada
				urlDefinitiva += variables[0] + "=" + codificada	#Añadimos el codigo que comprueba si es explotable a la url, como tiene un salto de linea eliminamos el ultimo caracter
				n = 1						#Utilizamos la variable n para hiterar los valores adicionales de la url si los hubiera
				while n < len(infoVariable):			#Si la url original tiene mas de una variable modificamos la primera con el codigo xss pero dejamos las siguientes intactas 
					urlDefinitiva += "&" + variables[n]
					otroValor = ''.join(infoVariable[n])
					urlDefinitiva += "=" + otroValor
					n += 1
				#print(urlDefinitiva)				#Se muestra la url resultante
				comprobarPagina(urlDefinitiva, linea[:-1])	#Se deja comentado para evitar saturar la pagina
