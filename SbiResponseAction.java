public package com.pay10.pg.action;

import org.slf4j.LoggerFactory;
import org.owasp.esapi.ESAPI;
import com.pay10.commons.user.User;
import java.io.PrintWriter;
import java.util.Iterator;
import com.pay10.commons.util.Constants;
import com.pay10.commons.util.AcquirerType;
import org.apache.commons.lang3.StringUtils;
import com.pay10.pg.core.util.ProcessManager;
import com.pay10.commons.util.TransactionManager;
import com.pay10.commons.util.PropertiesManager;
import com.fss.plugin.iPayPipe;
import org.apache.struts2.ServletActionContext;
import com.pay10.commons.util.FieldType;
import java.util.Map;
import java.util.HashMap;
import javax.servlet.http.HttpServletRequest;
import com.pay10.commons.util.Fields;
import com.pay10.pg.core.util.SbiUtil;
import com.pay10.pg.action.service.RetryTransactionProcessor;
import com.pay10.commons.dao.FieldsDao;
import com.pay10.commons.user.UserDao;
import org.springframework.beans.factory.annotation.Qualifier;
import com.pay10.pg.core.util.Processor;
import com.pay10.pg.core.util.ResponseCreator;
import org.springframework.beans.factory.annotation.Autowired;
import com.pay10.commons.api.TransactionControllerServiceProvider;
import org.slf4j.Logger;
import org.apache.struts2.interceptor.ServletRequestAware;

public class SbiResponseAction extends AbstractSecureAction implements ServletRequestAware
{
    private static Logger logger;
    private static final long serialVersionUID = 6155942791032490231L;
    @Autowired
    TransactionControllerServiceProvider transactionControllerServiceProvider;
    @Autowired
    private ResponseCreator responseCreator;
    @Autowired
    @Qualifier("updateProcessor")
    private Processor updateProcessor;
    @Autowired
    private UserDao userDao;
    @Autowired
    private FieldsDao fieldsDao;
    @Autowired
    private RetryTransactionProcessor retryTransactionProcessor;
    @Autowired
    private SbiUtil sbiUtil;
    private Fields responseMap;
    private HttpServletRequest httpRequest;
    
    public void setServletRequest(final HttpServletRequest hReq) {
        this.httpRequest = hReq;
    }
    
    public SbiResponseAction() {
        this.responseMap = null;
    }
    
    public String execute() {
        try {
            final Map<String, String[]> fieldMapObj = (Map<String, String[]>)this.httpRequest.getParameterMap();
            final Map<String, String> requestMap = new HashMap<String, String>();
            SbiResponseAction.logger.info("fieldMapObj >>>>> " + fieldMapObj.toString());
            for (final Map.Entry<String, String[]> entry : fieldMapObj.entrySet()) {
                try {
                    requestMap.put(entry.getKey(), entry.getValue()[0]);
                }
                catch (ClassCastException classCastException) {
                    SbiResponseAction.logger.error("Exception", (Throwable)classCastException);
                }
            }
            if (!this.sessionMap.isEmpty()) {
                final StringBuilder sb = new StringBuilder();
                for (final Map.Entry obj : this.sessionMap.entrySet()) {
                    sb.append(obj.getKey() + " = " + obj.getValue() + " ~");
                }
                SbiResponseAction.logger.info("sessionMap values >>> " + sb.toString());
            }
            else {
                SbiResponseAction.logger.info("Session Map is empty");
            }
            SbiResponseAction.logger.info("sessionMap >>>>>>>>>>>>>> " + this.sessionMap);
            Fields fields = new Fields();
            final Object fieldsObj = this.sessionMap.get((Object)"FIELDS");
            if (null != fieldsObj) {
                fields.put((Fields)fieldsObj);
            }
            if ("CC".equalsIgnoreCase(fields.get(FieldType.PAYMENT_TYPE.getName())) || "DC".equalsIgnoreCase(fields.get(FieldType.PAYMENT_TYPE.getName()))) {
                final PrintWriter out = ServletActionContext.getResponse().getWriter();
                final iPayPipe pipe = new iPayPipe();
                final String resourcePath = PropertiesManager.propertiesMap.get("SbiResourcePath");
                final String keystorePath = PropertiesManager.propertiesMap.get("SbikeystorePath");
                final String aliasName = PropertiesManager.propertiesMap.get("SbiAliasName");
                SbiResponseAction.logger.info("resourcePath " + resourcePath + " keystorePath " + keystorePath + " aliasName " + aliasName);
                pipe.setResourcePath(resourcePath);
                pipe.setKeystorePath(keystorePath);
                pipe.setAlias(aliasName);
                SbiResponseAction.logger.info("Response Received at SbiResponseAction");
                final int result = pipe.parseEncryptedResult(this.httpRequest.getParameter("trandata"));
                SbiResponseAction.logger.info("Response Received at SbiResponseAction Result is : " + result);
                String Result = "";
                String error = "";
                if (null == this.httpRequest.getParameter("ErrorText") && result == 0) {
                    Result = pipe.getResult();
                    final String PostDate = pipe.getDate();
                    final String refNum = pipe.getRef();
                    final String trackId = pipe.getTrackId();
                    final String tranId = pipe.getTransId();
                    final String amt = pipe.getAmt();
                    final String paymentId = pipe.getPaymentId();
                    final String auth = pipe.getAuth();
                    final String errorText = pipe.getError_text();
                    error = pipe.getError();
                    SbiResponseAction.logger.info("Result : " + Result + " PostDate : " + PostDate + " refNum : " + refNum + " trackId : " + trackId);
                    SbiResponseAction.logger.info("tranId : " + tranId + " amt : " + amt + " paymentId : " + paymentId + " auth : " + auth);
                    SbiResponseAction.logger.info("errorText : " + errorText + " error : " + error);
                    fields.put(FieldType.ACQ_ID.getName(), refNum);
                }
                else if (this.httpRequest.getParameter("ErrorText") != null) {
                    SbiResponseAction.logger.info(this.httpRequest.getParameter("ErrorText"));
                    error = pipe.getError();
                }
                else if (result != 0) {
                    SbiResponseAction.logger.info(pipe.getError());
                    error = pipe.getError();
                }
                if (Result.isEmpty() || (Result.equalsIgnoreCase("") && !Result.equalsIgnoreCase("CAPTURED"))) {
                    fields.put(FieldType.RESPONSE_MESSAGE.getName(), error);
                    fields.put(FieldType.STATUS.getName(), "FAILED");
                }
                else if (Result.equalsIgnoreCase("CAPTURED")) {
                    fields.put(FieldType.STATUS.getName(), "Captured");
                }
                SbiResponseAction.logger.info("<<<<<<<<<<< fields >>>>>>>>>>>>> " + fields.getFieldsAsString());
                SbiResponseAction.logger.info("Call updateProcessor");
                fields.put(FieldType.INTERNAL_ORIG_TXN_TYPE.getName(), fields.get(FieldType.TXNTYPE.getName()));
                fields.remove(FieldType.SBI_RESPONSE_FIELD.getName());
                final String newTxnId = TransactionManager.getNewTransactionId();
                fields.put(FieldType.TXN_ID.getName(), newTxnId);
                SbiResponseAction.logger.info("<<<<<<<<<<< after add/delete some parameter fields >>>>>>>>>>>>> " + fields.getFieldsAsString());
                ProcessManager.flow(this.updateProcessor, fields, true);
                SbiResponseAction.logger.info("updateProcessor operation completed for PG_REF : ");
                SbiResponseAction.logger.info("call ResponsePost Method For SBI Card Response : " + fields.getFieldsAsString());
                this.responseCreator.ResponsePost(fields);
            }
            else {
                SbiResponseAction.logger.info("SBI response received : " + this.responseMap);
                final String encdata = requestMap.get("encdata");
                SbiResponseAction.logger.info("Encrypted Response received from SBI: " + encdata);
                final String decrytedResponse = this.sbiUtil.decrypt(encdata);
                SbiResponseAction.logger.info("decrypted Response received from SBI: " + decrytedResponse);
                final String[] resparam = decrytedResponse.split("\\|");
                final Map<String, String> resParamMap = new HashMap<String, String>();
                for (final String param : resparam) {
                    final String[] parameterPair = param.split("=");
                    if (parameterPair.length > 1) {
                        resParamMap.put(parameterPair[0].trim(), parameterPair[1].trim());
                    }
                }
                SbiResponseAction.logger.info("<<<<<<<<<<<< resParamMap >>>>>>>>>>>>>>> " + resParamMap.toString());
                if (StringUtils.isBlank((CharSequence)fields.get(FieldType.PAY_ID.getName()))) {
                    SbiResponseAction.logger.info("FIELDS is blank in session Map, getting data from DB");
                    fields = this.fieldsDao.getPreviousForPgRefNum((String)resParamMap.get("Ref_no"));
                    final String internalRequestFields = fields.get(FieldType.INTERNAL_REQUEST_FIELDS.getName());
                    final String[] paramaters = internalRequestFields.split("~");
                    final Map<String, String> paramMap = new HashMap<String, String>();
                    for (final String param2 : paramaters) {
                        final String[] parameterPair2 = param2.split("=");
                        if (parameterPair2.length > 1) {
                            paramMap.put(parameterPair2[0].trim(), parameterPair2[1].trim());
                        }
                    }
                    fields.put(FieldType.RETURN_URL.getName(), (String)paramMap.get(FieldType.RETURN_URL.getName()));
                    this.sessionMap.put((Object)FieldType.RETURN_URL.getName(), (Object)paramMap.get(FieldType.RETURN_URL.getName()));
                    if (StringUtils.isNotBlank((CharSequence)paramMap.get(FieldType.INTERNAL_CUST_IP.getName()))) {
                        fields.put(FieldType.INTERNAL_CUST_IP.getName(), (String)paramMap.get(FieldType.INTERNAL_CUST_IP.getName()));
                    }
                    if (StringUtils.isNotBlank((CharSequence)paramMap.get(FieldType.INTERNAL_CUST_COUNTRY_NAME.getName()))) {
                        fields.put(FieldType.INTERNAL_CUST_COUNTRY_NAME.getName(), (String)paramMap.get(FieldType.INTERNAL_CUST_COUNTRY_NAME.getName()));
                    }
                }
                fields.put(FieldType.SBI_RESPONSE_FIELD.getName(), decrytedResponse);
                fields.logAllFields("Updated 3DS Recieved Map TxnType = " + fields.get(FieldType.TXNTYPE.getName()) + " Txn id = " + fields.get(FieldType.TXN_ID.getName()));
                fields.put(FieldType.ACQUIRER_TYPE.getName(), AcquirerType.SBI.getCode());
                if (StringUtils.isNotBlank((CharSequence)this.sessionMap.get((Object)FieldType.INTERNAL_ORIG_TXN_TYPE.getName()))) {
                    fields.put(FieldType.TXNTYPE.getName(), (String)this.sessionMap.get((Object)FieldType.INTERNAL_ORIG_TXN_TYPE.getName()));
                }
                if (StringUtils.isNotBlank((CharSequence)this.sessionMap.get((Object)FieldType.INTERNAL_CUST_IP.getName()))) {
                    fields.put(FieldType.INTERNAL_CUST_IP.getName(), (String)this.sessionMap.get((Object)FieldType.INTERNAL_CUST_IP.getName()));
                }
                if (StringUtils.isNotBlank((CharSequence)this.sessionMap.get((Object)FieldType.INTERNAL_CUST_COUNTRY_NAME.getName()))) {
                    fields.put(FieldType.INTERNAL_CUST_COUNTRY_NAME.getName(), (String)this.sessionMap.get((Object)FieldType.INTERNAL_CUST_COUNTRY_NAME.getName()));
                }
                if (StringUtils.isNotBlank((CharSequence)this.sessionMap.get((Object)FieldType.PAYMENTS_REGION.getName()))) {
                    fields.put(FieldType.PAYMENTS_REGION.getName(), (String)this.sessionMap.get((Object)FieldType.PAYMENTS_REGION.getName()));
                }
                if (StringUtils.isNotBlank((CharSequence)this.sessionMap.get((Object)FieldType.CARD_HOLDER_TYPE.getName()))) {
                    fields.put(FieldType.CARD_HOLDER_TYPE.getName(), (String)this.sessionMap.get((Object)FieldType.CARD_HOLDER_TYPE.getName()));
                }
                if (StringUtils.isNotBlank((CharSequence)this.sessionMap.get((Object)FieldType.OID.getName()))) {
                    fields.put(FieldType.OID.getName(), (String)this.sessionMap.get((Object)FieldType.OID.getName()));
                }
                fields.put(FieldType.INTERNAL_VALIDATE_HASH_YN.getName(), "N");
                SbiResponseAction.logger.info("SBI response received1 : " + this.responseMap);
                final Map<String, String> response = (Map<String, String>)this.transactionControllerServiceProvider.transact(fields, Constants.TXN_WS_SBI_PROCESSOR.getValue());
                this.responseMap = new Fields((Map)response);
                SbiResponseAction.logger.info("SBI response received2 : " + this.responseMap);
                final String pgFlag = (String)this.sessionMap.get((Object)FieldType.INTERNAL_IRCTC_YN.getName());
                if (StringUtils.isNotBlank((CharSequence)pgFlag)) {
                    this.responseMap.put(FieldType.INTERNAL_IRCTC_YN.getName(), pgFlag);
                }
                final User user = this.userDao.getUserClass(this.responseMap.get(FieldType.PAY_ID.getName()));
                final Fields Fields = new Fields();
                Fields.put(FieldType.ORDER_ID.getName(), fields.get(FieldType.ORDER_ID.getName()));
                Fields.put(FieldType.STATUS.getName(), fields.get(FieldType.STATUS.getName()));
                Fields.put(FieldType.MOP_TYPE.getName(), fields.get(FieldType.MOP_TYPE.getName()));
                if (StringUtils.isNotBlank((CharSequence)this.sessionMap.get((Object)FieldType.RETURN_URL.getName()))) {
                    fields.put(FieldType.RETURN_URL.getName(), (String)this.sessionMap.get((Object)FieldType.RETURN_URL.getName()));
                }
                final String cardIssuerBank = (String)this.sessionMap.get((Object)FieldType.INTERNAL_CARD_ISSUER_BANK.getName());
                final String cardIssuerCountry = (String)this.sessionMap.get((Object)FieldType.INTERNAL_CARD_ISSUER_COUNTRY.getName());
                if (StringUtils.isNotBlank((CharSequence)cardIssuerBank)) {
                    this.responseMap.put(FieldType.CARD_ISSUER_BANK.getName(), cardIssuerBank);
                }
                if (StringUtils.isNotBlank((CharSequence)cardIssuerCountry)) {
                    this.responseMap.put(FieldType.CARD_ISSUER_COUNTRY.getName(), cardIssuerCountry);
                }
                this.responseMap.put(FieldType.INTERNAL_SHOPIFY_YN.getName(), (String)this.sessionMap.get((Object)FieldType.INTERNAL_SHOPIFY_YN.getName()));
                this.responseMap.put(FieldType.IS_MERCHANT_HOSTED.getName(), (String)this.sessionMap.get((Object)FieldType.IS_MERCHANT_HOSTED.getName()));
                if (this.sessionMap != null) {
                    SbiResponseAction.logger.info("In validating session map for SBI Response Action");
                    this.sessionMap.put((Object)Constants.TRANSACTION_COMPLETE_FLAG.getValue(), (Object)Constants.Y_FLAG.getValue());
                    this.sessionMap.invalidate();
                }
                this.responseMap.remove(FieldType.HASH.getName());
                this.responseMap.remove(FieldType.TXN_KEY.getName());
                this.responseMap.remove(FieldType.ACQUIRER_TYPE.getName());
                this.responseMap.put(FieldType.IS_INTERNAL_REQUEST.getName(), "N");
                this.responseCreator.create(this.responseMap);
                this.responseCreator.ResponsePost(this.responseMap);
            }
        }
        catch (Exception exception) {
            SbiResponseAction.logger.error("2- SbiResponseAction Exception", (Throwable)exception);
            return "error";
        }
        return "none";
    }
    
    public static String encodeString(final String data) {
        return ESAPI.encoder().encodeForHTML(data);
    }
    
    static {
        SbiResponseAction.logger = LoggerFactory.getLogger(SbiResponseAction.class.getName());
    }
}class sbi {
    
}
