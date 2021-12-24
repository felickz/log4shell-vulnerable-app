/**
 * @name Log4J
 * @description MyLog4JDetector
 * @kind problem
 * @problem.severity warning
 * @precision low
 * @id java/Log4jInUse
 * @tags security
 *       
 */

import java

import java
import semmle.code.java.dataflow.DataFlow
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
//import semmle.code.java.security.XSS

import DataFlow::PathGraph

class Log4JConfig extends TaintTracking::Configuration {
    Log4JConfig() { this = "Log4jConfig" }
    override predicate isSource(DataFlow::Node source) { source instanceof RemoteFlowSource }
  
    override predicate isSink(DataFlow::Node sink) { sink.asParameter().getName() = "message"   }
}

from
  DataFlow::PathNode source, DataFlow::PathNode sink, Log4JConfig conf
where
  conf.hasFlowPath(source, sink)
  select sink.getNode(), source, sink, "Log4J RCE vulnerability detected due to $@.",
  source.getNode(), "user-provided value"