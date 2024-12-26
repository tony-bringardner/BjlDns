CREATE TABLE  dynamic_dns (
	id INT  NOT NULL auto_increment,
	name VARCHAR(100)  NOT NULL ,
	ip VARCHAR(50)  NOT NULL ,
	lastUpdate TIMESTAMP  NOT NULL ,
	status VARCHAR(50)  NOT NULL 
 )
