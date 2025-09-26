//+-------------------------------------------------------------------------
//
//  TaskMan - NT TaskManager
//  Copyright (C) Microsoft
//
//  File:       rtlmir.h
//
//  History:    Oct-11-24   aubymori  Created
//
//--------------------------------------------------------------------------
#pragma once
#include "precomp.h"

extern BOOL g_bMirroredOS;

BOOL Mirror_IsEnabledOS(void);
BOOL  Mirror_IsWindowMirroredRTL(HWND hWnd);
extern const DWORD dwNoMirrorBitmap;
extern const DWORD dwExStyleRTLMirrorWnd;
extern const DWORD dwExStyleNoInheritLayout;
extern const DWORD dwPreserveBitmap;

#define IS_MIRRORING_ENABLED()          Mirror_IsEnabledOS()
#define IS_WINDOW_RTL_MIRRORED(hwnd)    (g_bMirroredOS && Mirror_IsWindowMirroredRTL(hwnd))
#define DONTMIRRORBITMAP                dwNoMirrorBitmap
#define RTL_MIRRORED_WINDOW             dwExStyleRTLMirrorWnd
#define RTL_NOINHERITLAYOUT             dwExStyleNoInheritLayout
#define LAYOUT_PRESERVEBITMAP           dwPreserveBitmap