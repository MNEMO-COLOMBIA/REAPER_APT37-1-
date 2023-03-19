# REAPER_APT37-1-
Esta regla de detección se utiliza para identificar archivos maliciosos que pueden estar asociados con el grupo de amenazas "Segador"
 la regla utiliza una combinación de cadenas de texto y patrones de expresiones regulares para buscar características específicas en el archivo sospechoso. 
 La condición de la regla se cumple si el archivo comienza con la firma "MZ" (0x4d5a), tiene un tamaño menor de 1MB y contiene al menos una de las cadenas de texto mencionadas en la regla.
 Ó cumple con uno de los patrones de expresiones regulares definidos.
