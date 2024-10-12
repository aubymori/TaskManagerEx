//+-------------------------------------------------------------------------
//
//  TaskMan - NT TaskManager
//  Copyright (C) Microsoft
//
//  File:       rtlmir.cpp
//
//  History:    Oct-11-24   aubymori  Created
//
//--------------------------------------------------------------------------
#include "rtlmir.h"

const DWORD dwNoMirrorBitmap = NOMIRRORBITMAP;
const DWORD dwExStyleRTLMirrorWnd = WS_EX_LAYOUTRTL;
const DWORD dwExStyleNoInheritLayout = WS_EX_NOINHERITLAYOUT;
const DWORD dwPreserveBitmap = LAYOUT_BITMAPORIENTATIONPRESERVED;

/***************************************************************************\
* Mirror_IsEnabledOS
*
* returns TRUE if the mirroring APIs are enabled on the current OS.
*
* History:
* 02-Feb-1998 samera    Created
\***************************************************************************/
BOOL Mirror_IsEnabledOS(void)
{
    BOOL bRet = FALSE;

    if (IsOS(OS_WIN2000ORGREATER))
    {
        bRet = TRUE;
    }
    else if (IsOS(OS_WIN98ORGREATER) && GetSystemMetrics(SM_MIDEASTENABLED)) {
        bRet = TRUE;
    }

    return bRet;
}

/***************************************************************************\
* Mirror_IsWindowMirroredRTL
*
* returns TRUE if the window is RTL mirrored
*
* History:
* 02-Feb-1998 samera    Created
\***************************************************************************/
BOOL Mirror_IsWindowMirroredRTL(HWND hWnd)
{
    return (GetWindowLongA(hWnd, GWL_EXSTYLE) & WS_EX_LAYOUTRTL);
}