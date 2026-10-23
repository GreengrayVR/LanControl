#pragma once
#include "common.hpp"
#include <windows.h>

namespace lc::win {
bool elevated();
bool elevate(const QString &arguments);
void install();
void uninstall();
void applyUpdate(int version);
int dispatchService();
void reportRunning();
void launchAgents();
QString activeExecutable();
QString quote(const QString &text);
}
