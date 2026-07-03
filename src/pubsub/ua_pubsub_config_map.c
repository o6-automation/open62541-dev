/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * Copyright (c) 2025 Fraunhofer IOSB (Author: Andreas Ebner)
 */

#include <open62541/server_pubsub.h>

#ifdef UA_ENABLE_PUBSUB

#include "ua_pubsub_internal.h"

/* Mapping between the OPC UA Part 14 configuration DataTypes
 * (PubSubConnectionDataType, WriterGroupDataType, ...) and the internal
 * UA_*Config structures.
 *
 * The _fromDataType converters create a *borrowing view*: the returned config
 * references the memory of the source DataType and stays valid only as long as
 * the source is alive. This is sufficient for the UA_*_create functions which
 * deep-copy the config internally. The only exception is the PublisherId
 * (converted from the Variant representation) which allocates for String
 * PublisherIds. Callers must clear the config with the matching _clearView
 * function (never with the regular _clear which would free borrowed memory).
 *
 * Fields defined in Part 14 without a counterpart in the internal config
 * structures are marked with "TODO Part14" below. They are dropped with a
 * debug log until the internal structures are extended. */

UA_StatusCode
UA_PubSubConnectionConfig_fromDataType(const UA_PubSubConnectionDataType *src,
                                       UA_PubSubConnectionConfig *dst) {
    memset(dst, 0, sizeof(UA_PubSubConnectionConfig));

    dst->name = src->name;
    dst->enabled = src->enabled;
    dst->transportProfileUri = src->transportProfileUri;
    dst->connectionProperties.map = src->connectionProperties;
    dst->connectionProperties.mapSize = src->connectionPropertiesSize;

    /* The address is stored as a Variant internally. It can only be mapped if
     * the ExtensionObject is decoded. */
    if(src->address.encoding != UA_EXTENSIONOBJECT_DECODED)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    UA_Variant_setScalar(&dst->address, src->address.content.decoded.data,
                         src->address.content.decoded.type);

    /* Optional TransportSettings */
    if(src->transportSettings.encoding == UA_EXTENSIONOBJECT_DECODED) {
        UA_Variant_setScalar(&dst->connectionTransportSettings,
                             src->transportSettings.content.decoded.data,
                             src->transportSettings.content.decoded.type);
    }

    return UA_PublisherId_fromVariant(&dst->publisherId, &src->publisherId);
}

void
UA_PubSubConnectionConfig_clearView(UA_PubSubConnectionConfig *config) {
    UA_PublisherId_clear(&config->publisherId);
    memset(config, 0, sizeof(UA_PubSubConnectionConfig));
}

UA_StatusCode
UA_WriterGroupConfig_fromDataType(const UA_WriterGroupDataType *src,
                                  UA_WriterGroupConfig *dst) {
    memset(dst, 0, sizeof(UA_WriterGroupConfig));

    dst->name = src->name;
    dst->enabled = src->enabled;
    dst->writerGroupId = src->writerGroupId;
    dst->publishingInterval = src->publishingInterval;
    dst->keepAliveTime = src->keepAliveTime;
    dst->priority = src->priority;
    dst->securityMode = src->securityMode;
    dst->securityGroupId = src->securityGroupId;
    dst->securityKeyServices = src->securityKeyServices;
    dst->securityKeyServicesSize = src->securityKeyServicesSize;
    dst->maxNetworkMessageSize = src->maxNetworkMessageSize;
    dst->headerLayoutUri = src->headerLayoutUri;
    dst->localeIds = src->localeIds;
    dst->localeIdsSize = src->localeIdsSize;
    dst->transportSettings = src->transportSettings;
    dst->messageSettings = src->messageSettings;
    dst->groupProperties.map = src->groupProperties;
    dst->groupProperties.mapSize = src->groupPropertiesSize;

    /* Non-standard parameter. Fill up NetworkMessages with DataSetMessages up
     * to this count (or until MaxNetworkMessageSize is exceeded). */
    dst->maxEncapsulatedDataSetMessageCount = 255;

    /* The encoding is defined by the type of the MessageSettings. If no
     * MessageSettings are given, UADP is the default. */
    dst->encodingMimeType = UA_PUBSUB_ENCODING_UADP;
    if(src->messageSettings.encoding == UA_EXTENSIONOBJECT_DECODED &&
       src->messageSettings.content.decoded.type ==
           &UA_TYPES[UA_TYPES_JSONWRITERGROUPMESSAGEDATATYPE]) {
#ifdef UA_ENABLE_JSON_ENCODING
        dst->encodingMimeType = UA_PUBSUB_ENCODING_JSON;
#else
        return UA_STATUSCODE_BADNOTIMPLEMENTED;
#endif
    }

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_DataSetWriterConfig_fromDataType(const UA_DataSetWriterDataType *src,
                                    UA_DataSetWriterConfig *dst) {
    memset(dst, 0, sizeof(UA_DataSetWriterConfig));

    dst->name = src->name;
    dst->enabled = src->enabled;
    dst->dataSetWriterId = src->dataSetWriterId;
    dst->dataSetFieldContentMask = src->dataSetFieldContentMask;
    dst->keyFrameCount = src->keyFrameCount;
    dst->dataSetName = src->dataSetName;
    dst->messageSettings = src->messageSettings;
    dst->transportSettings = src->transportSettings;
    dst->dataSetWriterProperties.map = src->dataSetWriterProperties;
    dst->dataSetWriterProperties.mapSize = src->dataSetWriterPropertiesSize;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_ReaderGroupConfig_fromDataType(const UA_ReaderGroupDataType *src,
                                  UA_ReaderGroupConfig *dst) {
    memset(dst, 0, sizeof(UA_ReaderGroupConfig));

    dst->name = src->name;
    dst->enabled = src->enabled;
    dst->securityMode = src->securityMode;
    dst->securityGroupId = src->securityGroupId;
    dst->securityKeyServices = src->securityKeyServices;
    dst->securityKeyServicesSize = src->securityKeyServicesSize;
    dst->maxNetworkMessageSize = src->maxNetworkMessageSize;
    dst->transportSettings = src->transportSettings;
    dst->messageSettings = src->messageSettings;
    dst->groupProperties.map = src->groupProperties;
    dst->groupProperties.mapSize = src->groupPropertiesSize;

    /* The message encoding is detected from the transport profile of the
     * parent connection. Default to UADP here. */
    dst->encodingMimeType = UA_PUBSUB_ENCODING_UADP;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_DataSetReaderConfig_fromDataType(const UA_DataSetReaderDataType *src,
                                    UA_DataSetReaderConfig *dst) {
    memset(dst, 0, sizeof(UA_DataSetReaderConfig));

    dst->name = src->name;
    dst->enabled = src->enabled;
    dst->writerGroupId = src->writerGroupId;
    dst->dataSetWriterId = src->dataSetWriterId;
    dst->dataSetMetaData = src->dataSetMetaData;
    dst->dataSetFieldContentMask = src->dataSetFieldContentMask;
    dst->messageReceiveTimeout = src->messageReceiveTimeout;
    dst->messageSettings = src->messageSettings;
    dst->transportSettings = src->transportSettings;
    dst->keyFrameCount = src->keyFrameCount;
    dst->headerLayoutUri = src->headerLayoutUri;
    dst->securityMode = src->securityMode;
    dst->securityGroupId = src->securityGroupId;
    dst->securityKeyServices = src->securityKeyServices;
    dst->securityKeyServicesSize = src->securityKeyServicesSize;
    dst->dataSetReaderProperties.map = src->dataSetReaderProperties;
    dst->dataSetReaderProperties.mapSize = src->dataSetReaderPropertiesSize;

    /* The SubscribedDataSet is either an inline TargetVariablesDataType or a
     * reference to a StandaloneSubscribedDataSet (by name). A
     * SubscribedDataSetMirror is not supported. */
    const UA_ExtensionObject *sds = &src->subscribedDataSet;
    if(sds->encoding == UA_EXTENSIONOBJECT_DECODED) {
        if(sds->content.decoded.type == &UA_TYPES[UA_TYPES_TARGETVARIABLESDATATYPE]) {
            dst->subscribedDataSetType = UA_PUBSUB_SDS_TARGET;
            dst->subscribedDataSet.target =
                *(UA_TargetVariablesDataType*)sds->content.decoded.data;
        } else if(sds->content.decoded.type ==
                  &UA_TYPES[UA_TYPES_STANDALONESUBSCRIBEDDATASETREFDATATYPE]) {
            UA_StandaloneSubscribedDataSetRefDataType *ref =
                (UA_StandaloneSubscribedDataSetRefDataType*)sds->content.decoded.data;
            dst->linkedStandaloneSubscribedDataSetName = ref->dataSetName;
            dst->subscribedDataSetType = UA_PUBSUB_SDS_TARGET;
        } else if(sds->content.decoded.type ==
                  &UA_TYPES[UA_TYPES_SUBSCRIBEDDATASETMIRRORDATATYPE]) {
            return UA_STATUSCODE_BADNOTIMPLEMENTED;
        } else {
            return UA_STATUSCODE_BADINVALIDARGUMENT;
        }
    }

    /* The PublisherId allocates for String ids -- clear with _clearView. An
     * empty Variant leaves the default (Byte 0). */
    if(!UA_Variant_isEmpty(&src->publisherId))
        return UA_PublisherId_fromVariant(&dst->publisherId, &src->publisherId);

    return UA_STATUSCODE_GOOD;
}

void
UA_DataSetReaderConfig_clearView(UA_DataSetReaderConfig *config) {
    UA_PublisherId_clear(&config->publisherId);
    memset(config, 0, sizeof(UA_DataSetReaderConfig));
}

UA_StatusCode
UA_PublishedDataSetConfig_fromDataType(const UA_PublishedDataSetDataType *src,
                                       UA_PublishedDataSetConfig *dst) {
    memset(dst, 0, sizeof(UA_PublishedDataSetConfig));

    dst->name = src->name;
    dst->dataSetFolder = src->dataSetFolder;
    dst->dataSetFolderSize = src->dataSetFolderSize;
    dst->extensionFields.map = src->extensionFields;
    dst->extensionFields.mapSize = src->extensionFieldsSize;

    /* Only PublishedDataItems are supported so far */
    if(src->dataSetSource.encoding != UA_EXTENSIONOBJECT_DECODED)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    const UA_DataType *sourceType = src->dataSetSource.content.decoded.type;
    if(sourceType == &UA_TYPES[UA_TYPES_PUBLISHEDDATAITEMSDATATYPE]) {
        dst->publishedDataSetType = UA_PUBSUB_DATASET_PUBLISHEDITEMS;
    } else if(sourceType == &UA_TYPES[UA_TYPES_PUBLISHEDEVENTSDATATYPE]) {
        return UA_STATUSCODE_BADNOTIMPLEMENTED;
    } else {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    /* The number of published variables must match the metadata fields. The
     * fields are mapped with UA_DataSetFieldConfig_fromDataType. */
    UA_PublishedDataItemsDataType *pdi = (UA_PublishedDataItemsDataType*)
        src->dataSetSource.content.decoded.data;
    if(pdi->publishedDataSize != src->dataSetMetaData.fieldsSize)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    /* TODO Part14: parts of the DataSetMetaData (description, dataSetClassId)
     * are not preserved yet -- the PDS rebuilds its metadata from the field
     * configs */

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_DataSetFieldConfig_fromDataType(const UA_PublishedDataSetDataType *src,
                                   size_t fieldIndex, UA_DataSetFieldConfig *dst) {
    memset(dst, 0, sizeof(UA_DataSetFieldConfig));

    if(src->dataSetSource.encoding != UA_EXTENSIONOBJECT_DECODED ||
       src->dataSetSource.content.decoded.type !=
           &UA_TYPES[UA_TYPES_PUBLISHEDDATAITEMSDATATYPE])
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    UA_PublishedDataItemsDataType *pdi = (UA_PublishedDataItemsDataType*)
        src->dataSetSource.content.decoded.data;
    if(fieldIndex >= pdi->publishedDataSize ||
       fieldIndex >= src->dataSetMetaData.fieldsSize)
        return UA_STATUSCODE_BADINVALIDARGUMENT;

    const UA_FieldMetaData *fmd = &src->dataSetMetaData.fields[fieldIndex];
    dst->dataSetFieldType = UA_PUBSUB_DATASETFIELD_VARIABLE;
    dst->field.variable.configurationVersion =
        src->dataSetMetaData.configurationVersion;
    dst->field.variable.fieldNameAlias = fmd->name;
    dst->field.variable.promotedField =
        (fmd->fieldFlags & UA_DATASETFIELDFLAGS_PROMOTEDFIELD) != 0;
    dst->field.variable.publishParameters = pdi->publishedData[fieldIndex];
    dst->field.variable.maxStringLength = fmd->maxStringLength;
    dst->field.variable.description = fmd->description;
    dst->field.variable.dataSetFieldId = fmd->dataSetFieldId;

    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_SubscribedDataSetConfig_fromDataType(const UA_StandaloneSubscribedDataSetDataType *src,
                                        UA_SubscribedDataSetConfig *dst) {
    memset(dst, 0, sizeof(UA_SubscribedDataSetConfig));

    dst->name = src->name;
    dst->dataSetMetaData = src->dataSetMetaData;
    dst->dataSetFolder = src->dataSetFolder;
    dst->dataSetFolderSize = src->dataSetFolderSize;

    const UA_ExtensionObject *sds = &src->subscribedDataSet;
    if(sds->encoding == UA_EXTENSIONOBJECT_DECODED &&
       sds->content.decoded.type == &UA_TYPES[UA_TYPES_TARGETVARIABLESDATATYPE]) {
        dst->subscribedDataSetType = UA_PUBSUB_SDS_TARGET;
        dst->subscribedDataSet.target =
            *(UA_TargetVariablesDataType*)sds->content.decoded.data;
    } else if(sds->encoding == UA_EXTENSIONOBJECT_DECODED &&
              sds->content.decoded.type ==
                  &UA_TYPES[UA_TYPES_SUBSCRIBEDDATASETMIRRORDATATYPE]) {
        return UA_STATUSCODE_BADNOTIMPLEMENTED;
    } else {
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    }

    return UA_STATUSCODE_GOOD;
}

/* The _toDataType converters create a deep copy. The enabled flag is not part
 * of most internal configs in a meaningful way for a running component (it
 * only controls auto-enabling at creation). The caller sets dst->enabled from
 * the current component state. */

UA_StatusCode
UA_PubSubConnectionConfig_toDataType(const UA_PubSubConnectionConfig *src,
                                     UA_PubSubConnectionDataType *dst) {
    UA_PubSubConnectionDataType_init(dst);

    UA_StatusCode res = UA_String_copy(&src->name, &dst->name);
    res |= UA_String_copy(&src->transportProfileUri, &dst->transportProfileUri);
    res |= UA_Array_copy(src->connectionProperties.map,
                         src->connectionProperties.mapSize,
                         (void**)&dst->connectionProperties,
                         &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    if(res == UA_STATUSCODE_GOOD)
        dst->connectionPropertiesSize = src->connectionProperties.mapSize;

    /* The PublisherId as Variant (shallow) and deep-copy into dst */
    UA_Variant pubIdVar;
    UA_PublisherId_toVariant(&src->publisherId, &pubIdVar);
    res |= UA_Variant_copy(&pubIdVar, &dst->publisherId);

    /* The address Variant is expected to hold a scalar (e.g.
     * NetworkAddressUrlDataType) */
    if(src->address.data && UA_Variant_isScalar(&src->address)) {
        res |= UA_ExtensionObject_setValueCopy(&dst->address, src->address.data,
                                               src->address.type);
    }

    if(src->connectionTransportSettings.data &&
       UA_Variant_isScalar(&src->connectionTransportSettings)) {
        res |= UA_ExtensionObject_setValueCopy(&dst->transportSettings,
                                               src->connectionTransportSettings.data,
                                               src->connectionTransportSettings.type);
    }

    if(res != UA_STATUSCODE_GOOD)
        UA_PubSubConnectionDataType_clear(dst);
    return res;
}

UA_StatusCode
UA_WriterGroupConfig_toDataType(const UA_WriterGroupConfig *src,
                                UA_WriterGroupDataType *dst) {
    UA_WriterGroupDataType_init(dst);

    dst->writerGroupId = src->writerGroupId;
    dst->publishingInterval = src->publishingInterval;
    dst->keepAliveTime = src->keepAliveTime;
    dst->priority = src->priority;
    dst->securityMode = src->securityMode;
    dst->maxNetworkMessageSize = src->maxNetworkMessageSize;

    UA_StatusCode res = UA_String_copy(&src->name, &dst->name);
    res |= UA_String_copy(&src->securityGroupId, &dst->securityGroupId);
    res |= UA_String_copy(&src->headerLayoutUri, &dst->headerLayoutUri);
    res |= UA_ExtensionObject_copy(&src->transportSettings, &dst->transportSettings);
    res |= UA_ExtensionObject_copy(&src->messageSettings, &dst->messageSettings);
    res |= UA_Array_copy(src->groupProperties.map, src->groupProperties.mapSize,
                         (void**)&dst->groupProperties,
                         &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    if(res == UA_STATUSCODE_GOOD)
        dst->groupPropertiesSize = src->groupProperties.mapSize;
    res |= UA_Array_copy(src->localeIds, src->localeIdsSize,
                         (void**)&dst->localeIds, &UA_TYPES[UA_TYPES_STRING]);
    if(res == UA_STATUSCODE_GOOD)
        dst->localeIdsSize = src->localeIdsSize;
    res |= UA_Array_copy(src->securityKeyServices, src->securityKeyServicesSize,
                         (void**)&dst->securityKeyServices,
                         &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    if(res == UA_STATUSCODE_GOOD)
        dst->securityKeyServicesSize = src->securityKeyServicesSize;

    if(res != UA_STATUSCODE_GOOD)
        UA_WriterGroupDataType_clear(dst);
    return res;
}

UA_StatusCode
UA_DataSetWriterConfig_toDataType(const UA_DataSetWriterConfig *src,
                                  UA_DataSetWriterDataType *dst) {
    UA_DataSetWriterDataType_init(dst);

    dst->dataSetWriterId = src->dataSetWriterId;
    dst->keyFrameCount = src->keyFrameCount;
    dst->dataSetFieldContentMask = src->dataSetFieldContentMask;

    UA_StatusCode res = UA_String_copy(&src->name, &dst->name);
    res |= UA_String_copy(&src->dataSetName, &dst->dataSetName);
    res |= UA_ExtensionObject_copy(&src->messageSettings, &dst->messageSettings);
    res |= UA_ExtensionObject_copy(&src->transportSettings, &dst->transportSettings);
    res |= UA_Array_copy(src->dataSetWriterProperties.map,
                         src->dataSetWriterProperties.mapSize,
                         (void**)&dst->dataSetWriterProperties,
                         &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    if(res == UA_STATUSCODE_GOOD)
        dst->dataSetWriterPropertiesSize = src->dataSetWriterProperties.mapSize;

    if(res != UA_STATUSCODE_GOOD)
        UA_DataSetWriterDataType_clear(dst);
    return res;
}

UA_StatusCode
UA_ReaderGroupConfig_toDataType(const UA_ReaderGroupConfig *src,
                                UA_ReaderGroupDataType *dst) {
    UA_ReaderGroupDataType_init(dst);

    dst->securityMode = src->securityMode;
    dst->maxNetworkMessageSize = src->maxNetworkMessageSize;

    UA_StatusCode res = UA_String_copy(&src->name, &dst->name);
    res |= UA_String_copy(&src->securityGroupId, &dst->securityGroupId);
    res |= UA_ExtensionObject_copy(&src->transportSettings, &dst->transportSettings);
    res |= UA_ExtensionObject_copy(&src->messageSettings, &dst->messageSettings);
    res |= UA_Array_copy(src->groupProperties.map, src->groupProperties.mapSize,
                         (void**)&dst->groupProperties,
                         &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    if(res == UA_STATUSCODE_GOOD)
        dst->groupPropertiesSize = src->groupProperties.mapSize;
    res |= UA_Array_copy(src->securityKeyServices, src->securityKeyServicesSize,
                         (void**)&dst->securityKeyServices,
                         &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    if(res == UA_STATUSCODE_GOOD)
        dst->securityKeyServicesSize = src->securityKeyServicesSize;

    if(res != UA_STATUSCODE_GOOD)
        UA_ReaderGroupDataType_clear(dst);
    return res;
}

UA_StatusCode
UA_DataSetReaderConfig_toDataType(const UA_DataSetReaderConfig *src,
                                  UA_DataSetReaderDataType *dst) {
    UA_DataSetReaderDataType_init(dst);

    dst->writerGroupId = src->writerGroupId;
    dst->dataSetWriterId = src->dataSetWriterId;
    dst->dataSetFieldContentMask = src->dataSetFieldContentMask;
    dst->messageReceiveTimeout = src->messageReceiveTimeout;
    dst->keyFrameCount = src->keyFrameCount;
    dst->securityMode = src->securityMode;

    UA_StatusCode res = UA_String_copy(&src->name, &dst->name);
    res |= UA_DataSetMetaDataType_copy(&src->dataSetMetaData, &dst->dataSetMetaData);
    res |= UA_ExtensionObject_copy(&src->messageSettings, &dst->messageSettings);
    res |= UA_ExtensionObject_copy(&src->transportSettings, &dst->transportSettings);
    res |= UA_String_copy(&src->headerLayoutUri, &dst->headerLayoutUri);
    res |= UA_String_copy(&src->securityGroupId, &dst->securityGroupId);
    res |= UA_Array_copy(src->securityKeyServices, src->securityKeyServicesSize,
                         (void**)&dst->securityKeyServices,
                         &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    if(res == UA_STATUSCODE_GOOD)
        dst->securityKeyServicesSize = src->securityKeyServicesSize;
    res |= UA_Array_copy(src->dataSetReaderProperties.map,
                         src->dataSetReaderProperties.mapSize,
                         (void**)&dst->dataSetReaderProperties,
                         &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    if(res == UA_STATUSCODE_GOOD)
        dst->dataSetReaderPropertiesSize = src->dataSetReaderProperties.mapSize;

    UA_Variant pubIdVar;
    UA_PublisherId_toVariant(&src->publisherId, &pubIdVar);
    res |= UA_Variant_copy(&pubIdVar, &dst->publisherId);

    /* Encode the SubscribedDataSet. A configured standalone SDS name takes
     * precedence over inline TargetVariables. */
    if(!UA_String_isEmpty(&src->linkedStandaloneSubscribedDataSetName)) {
        UA_StandaloneSubscribedDataSetRefDataType *ref =
            UA_StandaloneSubscribedDataSetRefDataType_new();
        if(!ref) {
            res |= UA_STATUSCODE_BADOUTOFMEMORY;
        } else {
            res |= UA_String_copy(&src->linkedStandaloneSubscribedDataSetName,
                                  &ref->dataSetName);
            UA_ExtensionObject_setValue(&dst->subscribedDataSet, ref,
                &UA_TYPES[UA_TYPES_STANDALONESUBSCRIBEDDATASETREFDATATYPE]);
        }
    } else if(src->subscribedDataSetType == UA_PUBSUB_SDS_TARGET) {
        UA_TargetVariablesDataType *tvs = UA_TargetVariablesDataType_new();
        if(!tvs) {
            res |= UA_STATUSCODE_BADOUTOFMEMORY;
        } else {
            res |= UA_TargetVariablesDataType_copy(&src->subscribedDataSet.target, tvs);
            UA_ExtensionObject_setValue(&dst->subscribedDataSet, tvs,
                &UA_TYPES[UA_TYPES_TARGETVARIABLESDATATYPE]);
        }
    }

    if(res != UA_STATUSCODE_GOOD)
        UA_DataSetReaderDataType_clear(dst);
    return res;
}

/* The PublishedDataSet export uses the component (not only the config): the
 * internally maintained DataSetMetaData and the DataSetField list define the
 * exported dataSetMetaData and dataSetSource. */
UA_StatusCode
UA_PublishedDataSet_toDataType(const UA_PublishedDataSet *pds,
                               UA_PublishedDataSetDataType *dst) {
    if(pds->config.publishedDataSetType != UA_PUBSUB_DATASET_PUBLISHEDITEMS)
        return UA_STATUSCODE_BADNOTIMPLEMENTED;

    UA_PublishedDataSetDataType_init(dst);

    UA_StatusCode res = UA_String_copy(&pds->config.name, &dst->name);
    res |= UA_DataSetMetaDataType_copy(&pds->dataSetMetaData, &dst->dataSetMetaData);
    res |= UA_Array_copy(pds->config.dataSetFolder, pds->config.dataSetFolderSize,
                         (void**)&dst->dataSetFolder, &UA_TYPES[UA_TYPES_STRING]);
    if(res == UA_STATUSCODE_GOOD)
        dst->dataSetFolderSize = pds->config.dataSetFolderSize;
    res |= UA_Array_copy(pds->config.extensionFields.map,
                         pds->config.extensionFields.mapSize,
                         (void**)&dst->extensionFields,
                         &UA_TYPES[UA_TYPES_KEYVALUEPAIR]);
    if(res == UA_STATUSCODE_GOOD)
        dst->extensionFieldsSize = pds->config.extensionFields.mapSize;

    UA_PublishedDataItemsDataType *pdi = UA_PublishedDataItemsDataType_new();
    if(!pdi) {
        UA_PublishedDataSetDataType_clear(dst);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    pdi->publishedData = (UA_PublishedVariableDataType*)
        UA_Array_new(pds->fieldSize, &UA_TYPES[UA_TYPES_PUBLISHEDVARIABLEDATATYPE]);
    if(pds->fieldSize > 0 && !pdi->publishedData) {
        UA_free(pdi);
        UA_PublishedDataSetDataType_clear(dst);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    pdi->publishedDataSize = pds->fieldSize;

    size_t i = 0;
    UA_DataSetField *dsf;
    TAILQ_FOREACH(dsf, &pds->fields, listEntry) {
        res |= UA_PublishedVariableDataType_copy(
            &dsf->config.field.variable.publishParameters, &pdi->publishedData[i]);
        i++;
    }
    UA_ExtensionObject_setValue(&dst->dataSetSource, pdi,
                                &UA_TYPES[UA_TYPES_PUBLISHEDDATAITEMSDATATYPE]);

    if(res != UA_STATUSCODE_GOOD)
        UA_PublishedDataSetDataType_clear(dst);
    return res;
}

UA_StatusCode
UA_SubscribedDataSetConfig_toDataType(const UA_SubscribedDataSetConfig *src,
                                      UA_StandaloneSubscribedDataSetDataType *dst) {
    if(src->subscribedDataSetType != UA_PUBSUB_SDS_TARGET)
        return UA_STATUSCODE_BADNOTIMPLEMENTED;

    UA_StandaloneSubscribedDataSetDataType_init(dst);

    UA_StatusCode res = UA_String_copy(&src->name, &dst->name);
    res |= UA_DataSetMetaDataType_copy(&src->dataSetMetaData, &dst->dataSetMetaData);
    res |= UA_Array_copy(src->dataSetFolder, src->dataSetFolderSize,
                         (void**)&dst->dataSetFolder, &UA_TYPES[UA_TYPES_STRING]);
    if(res == UA_STATUSCODE_GOOD)
        dst->dataSetFolderSize = src->dataSetFolderSize;

    UA_TargetVariablesDataType *tvs = UA_TargetVariablesDataType_new();
    if(!tvs) {
        UA_StandaloneSubscribedDataSetDataType_clear(dst);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }
    res |= UA_TargetVariablesDataType_copy(&src->subscribedDataSet.target, tvs);
    UA_ExtensionObject_setValue(&dst->subscribedDataSet, tvs,
                                &UA_TYPES[UA_TYPES_TARGETVARIABLESDATATYPE]);

    if(res != UA_STATUSCODE_GOOD)
        UA_StandaloneSubscribedDataSetDataType_clear(dst);
    return res;
}

#endif /* UA_ENABLE_PUBSUB */
