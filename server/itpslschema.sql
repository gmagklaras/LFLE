-- MySQL dump 10.13  Distrib 5.1.44, for redhat-linux-gnu (x86_64)
--
-- Host: localhost    Database: itpsl
-- ------------------------------------------------------
-- Server version	5.1.44

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `fileinfo`
--

DROP TABLE IF EXISTS `fileinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `fileinfo` (
  `fileaccessid` bigint NOT NULL AUTO_INCREMENT,
  `shasum` char(40) NOT NULL,
  `filename` varchar(300) NOT NULL,
  `uid` mediumint NOT NULL,
  `command` text NOT NULL,
  `pid` mediumint NOT NULL,
  `ppid` mediumint NOT NULL,
  `cyear` smallint(6) NOT NULL,
  `cmonth` tinyint(4) NOT NULL,
  `cday` tinyint(4) NOT NULL,
  `cmin` tinyint(4) NOT NULL,
  `chour` tinyint(4) NOT NULL,
  `csec` tinyint(4) NOT NULL,
  `dyear` smallint(6) DEFAULT NULL,
  `dmonth` tinyint(4) DEFAULT NULL,
  `dday` tinyint(4) DEFAULT NULL,
  `dhour` tinyint(4) DEFAULT NULL,
  `dmin` tinyint(4) DEFAULT NULL,
  `dsec` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`fileaccessid`)
) ENGINE=MyISAM AUTO_INCREMENT=246450 DEFAULT CHARSET=ucs2;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hostinfo`
--

DROP TABLE IF EXISTS `hostinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `hostinfo` (
  `cid` mediumint NOT NULL,
  `hostname` varchar(70) NOT NULL,
  `os` tinytext NOT NULL,
  `osver` tinytext NOT NULL,
  `vendor` tinytext,
  `vendormodel` tinytext,
  `timezone` tinytext NOT NULL,
  PRIMARY KEY (`cid`)
) ENGINE=MyISAM DEFAULT CHARSET=ucs2;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `hostinfo`
--

DROP TABLE IF EXISTS `groupinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `groupinfo` (
  `groupid` mediumint NOT NULL AUTO_INCREMENT,
  `groupname` tinytext NOT NULL,
  `gid` mediumint NOT NULL,
  `shasum` char(40) NOT NULL,
  `groupusers` text NOT NULL,
  `cday` tinyint(4) NOT NULL,
  `cmin` tinyint(4) NOT NULL,
  `chour` tinyint(4) NOT NULL,
  `csec` tinyint(4) NOT NULL,
  `cyear` int(11) DEFAULT NULL,
  `cmonth` tinyint(4) DEFAULT NULL,
  `dyear` int(11) DEFAULT NULL,
  `dmonth` tinyint(4) DEFAULT NULL,
  `dhour` tinyint(4) DEFAULT NULL,
  `dmin` tinyint(4) DEFAULT NULL,
  `dsec` tinyint(4) DEFAULT NULL,
  `dday` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`groupid`)
) ENGINE=MyISAM DEFAULT CHARSET=ucs2;
/*!40101 SET character_set_client = @saved_cs_client */;

DROP TABLE IF EXISTS `userinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `userinfo` (
  `userid` mediumint NOT NULL AUTO_INCREMENT,
  `shasum` char(40) NOT NULL,
  `uid` mediumint NOT NULL,
  `gid` mediumint NOT NULL,
  `cday` tinyint(4) NOT NULL,
  `cmin` tinyint(4) NOT NULL,
  `chour` tinyint(4) NOT NULL,
  `csec` tinyint(4) NOT NULL,
  `myear` int(11) DEFAULT NULL,
  `mmonth` tinyint(4) DEFAULT NULL,
  `mhour` tinyint(4) DEFAULT NULL,
  `mmin` tinyint(4) DEFAULT NULL,
  `msec` tinyint(4) DEFAULT NULL,
  `mday` tinyint(4) DEFAULT NULL,
  `dyear` int(11) DEFAULT NULL,
  `dmonth` tinyint(4) DEFAULT NULL,
  `dhour` tinyint(4) DEFAULT NULL,
  `dmin` tinyint(4) DEFAULT NULL,
  `dsec` tinyint(4) DEFAULT NULL,
  `dday` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`userid`)
) ENGINE=MyISAM DEFAULT CHARSET=ucs2;
/*!40101 SET character_set_client = @saved_cs_client */;
--
-- Table structure for table `hwinfo`
--

DROP TABLE IF EXISTS `hwinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `hwinfo` (
  `hwdevid` bigint(20) unsigned NOT NULL AUTO_INCREMENT,
  `shasum` char(40) NOT NULL,
  `cyear` smallint(6) NOT NULL,
  `cmonth` tinyint(4) NOT NULL,
  `cday` tinyint(4) NOT NULL,
  `chour` tinyint(4) NOT NULL,
  `cmin` tinyint(4) NOT NULL,
  `csec` tinyint(4) NOT NULL,
  `devbus` tinytext NOT NULL,
  `devstring` text NOT NULL,
  `devvendor` text NOT NULL,
  `userslogged` text NOT NULL,
  `dyear` smallint(6) DEFAULT NULL,
  `dmonth` tinyint(4) DEFAULT NULL,
  `dday` tinyint(4) DEFAULT NULL,
  `dhour` tinyint(4) DEFAULT NULL,
  `dmin` tinyint(4) DEFAULT NULL,
  `dsec` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`hwdevid`)
) ENGINE=MyISAM DEFAULT CHARSET=latin1 COMMENT='Holds information about hardware device connection and removal';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `urlinfo`
--
DROP TABLE IF EXISTS `urlinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `urlinfo` (
  `urlinfo` bigint(20) NOT NULL AUTO_INCREMENT,
  `cyear` smallint(6) NOT NULL,
  `cmonth` tinyint(4) NOT NULL,
  `cday` tinyint(4) NOT NULL,
  `chour` tinyint(4) NOT NULL,
  `cmin` tinyint(4) NOT NULL,
  `csec` tinyint(4) NOT NULL,
  `sourceip` tinytext NOT NULL,
  `destip` tinytext NOT NULL,
  `url` text NOT NULL,
  `users` tinytext NOT NULL,
  PRIMARY KEY (`urlinfo`)
) ENGINE=MyISAM AUTO_INCREMENT=2075 DEFAULT CHARSET=latin1 COMMENT='This table contains the URLs info';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `netinfo`
--

DROP TABLE IF EXISTS `netinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `netinfo` (
  `endpointinfo` bigint(20) NOT NULL AUTO_INCREMENT,
  `cyear` smallint(6) NOT NULL,
  `cmonth` tinyint(4) NOT NULL,
  `cday` tinyint(4) NOT NULL,
  `chour` tinyint(4) NOT NULL,
  `cmin` tinyint(4) NOT NULL,
  `csec` tinyint(4) NOT NULL,
  `transport` tinytext NOT NULL,
  `sourceip` tinytext NOT NULL,
  `sourcefqdn` tinytext,
  `sourceport` smallint(6) NOT NULL,
  `destip` tinytext NOT NULL,
  `destfqdn` tinytext,
  `destport` smallint(6) NOT NULL,
  `ipversion` tinyint(4) NOT NULL,
  `pid` mediumint NOT NULL,
  `uid` mediumint NOT NULL,
  `dyear` smallint(6) DEFAULT NULL,
  `dmonth` tinyint(4) DEFAULT NULL,
  `dday` tinyint(4) DEFAULT NULL,
  `dhour` tinyint(4) DEFAULT NULL,
  `dmin` tinyint(4) DEFAULT NULL,
  `dsec` tinyint(4) DEFAULT NULL COMMENT 'sourcefqdn and destfqdn are populated \nas batch jobs to limit performance degradation.\n\n',
  `shasum` char(40) NOT NULL,
  PRIMARY KEY (`endpointinfo`)
) ENGINE=MyISAM AUTO_INCREMENT=2075 DEFAULT CHARSET=latin1 COMMENT='This table contains the endpoint info';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `netint`
--

DROP TABLE IF EXISTS `netint`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `netint` (
  `shasum` char(40) NOT NULL,
  `ipversion` tinyint(4) NOT NULL,
  `ip` tinytext NOT NULL,
  `subnet` tinytext NOT NULL,
  `macaddr` tinytext NOT NULL,
  `cyear` smallint(6) NOT NULL,
  `cmonth` tinyint(4) NOT NULL,
  `cday` tinyint(4) NOT NULL,
  `chour` tinyint(4) NOT NULL,
  `cmin` tinyint(4) NOT NULL,
  `csec` tinyint(4) NOT NULL,
  `dyear` smallint(6) DEFAULT NULL,
  `dmonth` tinyint(4) DEFAULT NULL,
  `dday` tinyint(4) DEFAULT NULL,
  `dhour` tinyint(4) DEFAULT NULL,
  `dmin` tinyint(4) DEFAULT NULL,
  `dsec` tinyint(4) DEFAULT NULL COMMENT 'If a network interface has both\nan IPv4 and IPv6 address\n, we count them separately\n(one IP per Interface).\n',
  `intname` text NOT NULL,
  `netintid` bigint(20) NOT NULL AUTO_INCREMENT,
  PRIMARY KEY (`netintid`)
) ENGINE=MyISAM AUTO_INCREMENT=147 DEFAULT CHARSET=latin1 COMMENT='This table describes the per-host network interfaces. ';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `netroute`
--

DROP TABLE IF EXISTS `netroute`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `netroute` (
  `routeid` bigint(20) NOT NULL AUTO_INCREMENT,
  `ipversion` tinyint(4) NOT NULL,
  `netip` tinytext NOT NULL,
  `routenetmask` tinytext NOT NULL,
  `defgw` tinytext,
  `cyear` smallint(6) NOT NULL,
  `cmonth` tinyint(4) NOT NULL,
  `cday` tinyint(4) NOT NULL,
  `chour` tinyint(4) NOT NULL,
  `cmin` tinytext NOT NULL,
  `csec` tinyint(4) NOT NULL,
  `dyear` smallint(6) DEFAULT NULL,
  `dmonth` tinyint(4) DEFAULT NULL,
  `dday` tinyint(4) DEFAULT NULL,
  `dhour` tinyint(4) DEFAULT NULL,
  `dmin` tinyint(4) DEFAULT NULL,
  `dsec` tinyint(4) DEFAULT NULL,
  `shasum` char(40) NOT NULL,
  `intname` tinytext NOT NULL,
  PRIMARY KEY (`routeid`)
) ENGINE=MyISAM AUTO_INCREMENT=233 DEFAULT CHARSET=latin1 COMMENT='This describes routing table data per host.\n';
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Table structure for table `psinfo`
--

DROP TABLE IF EXISTS `psinfo`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!40101 SET character_set_client = utf8 */;
CREATE TABLE `psinfo` (
  `psentity` bigint(20) NOT NULL AUTO_INCREMENT,
  `shanorm` char(40) NOT NULL,
  `shafull` char(40) NOT NULL,
  `uid` mediumint NOT NULL,
  `pid` mediumint NOT NULL,
  `ppid` mediumint NOT NULL,
  `command` text NOT NULL,
  `arguments` mediumtext,
  `cyear` smallint(6) NOT NULL,
  `cmonth` tinyint(4) NOT NULL,
  `cday` tinyint(4) NOT NULL,
  `cmin` tinyint(4) NOT NULL,
  `chour` tinyint(4) NOT NULL,
  `csec` tinyint(4) NOT NULL,
  `dyear` smallint(6) DEFAULT NULL,
  `dmonth` tinyint(4) DEFAULT NULL,
  `dday` tinyint(4) DEFAULT NULL,
  `dhour` tinyint(4) DEFAULT NULL,
  `dmin` tinyint(4) DEFAULT NULL,
  `dsec` tinyint(4) DEFAULT NULL,
  PRIMARY KEY (`psentity`)
) ENGINE=MyISAM AUTO_INCREMENT=19470 DEFAULT CHARSET=latin1 COMMENT='This holds per host process execution data';
/*!40101 SET character_set_client = @saved_cs_client */;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2010-04-28  2:18:23
