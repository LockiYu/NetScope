#include "netscope/protocol/protocol_model.h"

#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QString>

#include <limits>

namespace netscope::protocol {
namespace {

QString validation_name(const validation_status validation) {
    switch (validation) {
    case validation_status::not_checked:
        return QStringLiteral("not_checked");
    case validation_status::valid:
        return QStringLiteral("valid");
    case validation_status::invalid:
        return QStringLiteral("invalid");
    case validation_status::warning:
        return QStringLiteral("warning");
    }
    return QStringLiteral("not_checked");
}

QJsonArray warnings_to_json(const std::vector<std::string>& warnings) {
    QJsonArray result;
    for (const auto& warning : warnings) {
        result.append(QString::fromStdString(warning));
    }
    return result;
}

QJsonObject range_to_json(const byte_range range) {
    return QJsonObject{
        {QStringLiteral("offset"), static_cast<double>(range.offset)},
        {QStringLiteral("length"), static_cast<double>(range.length)},
    };
}

QJsonObject field_to_json(const protocol_field& field) {
    QJsonObject result{
        {QStringLiteral("name"), QString::fromStdString(field.name)},
        {QStringLiteral("raw_value"), QString::fromStdString(field.raw_value)},
        {QStringLiteral("display_value"), QString::fromStdString(field.display_value)},
        {QStringLiteral("bytes"), range_to_json(field.bytes)},
        {QStringLiteral("validation"), validation_name(field.validation)},
        {QStringLiteral("warnings"), warnings_to_json(field.warnings)},
    };

    if (field.bit_offset.has_value()) {
        result.insert(
            QStringLiteral("bit_offset"),
            static_cast<int>(field.bit_offset.value()));
    }
    if (field.bit_length.has_value()) {
        result.insert(
            QStringLiteral("bit_length"),
            static_cast<int>(field.bit_length.value()));
    }

    return result;
}

QJsonObject node_to_json(const protocol_node& node) {
    QJsonArray fields;
    for (const auto& field : node.fields) {
        fields.append(field_to_json(field));
    }

    QJsonArray children;
    for (const auto& child : node.children) {
        children.append(node_to_json(child));
    }

    return QJsonObject{
        {QStringLiteral("name"), QString::fromStdString(node.name)},
        {QStringLiteral("bytes"), range_to_json(node.bytes)},
        {QStringLiteral("fields"), fields},
        {QStringLiteral("children"), children},
        {QStringLiteral("warnings"), warnings_to_json(node.warnings)},
    };
}

}  // namespace

bool byte_range::contains(const std::size_t byte_offset) const noexcept {
    return byte_offset >= offset && byte_offset - offset < length;
}

std::string to_json(const protocol_node& node) {
    const QJsonDocument document{node_to_json(node)};
    return document.toJson(QJsonDocument::Compact).toStdString();
}

}  // namespace netscope::protocol

