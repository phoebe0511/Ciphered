/*
 *  ProgressDialog.cpp
 *
 *  Copyright (C) 2006, 2008
 *  Paul E. Jones <paulej@packetizer.com>
 *  All Rights Reserved.
 *
 ******************************************************************************
 *  $Id: ProgressDialog.h,v 1.2 2008/09/01 10:40:44 paulej Exp $
 ******************************************************************************
 *
 *  This file defines a simple progress box class for showing the progress
 *  of file encryption and decryption.
 *
 */

#pragma once

#include "resource.h"       // main symbols
#include <atlhost.h>

class ProgressDialog : public CAxDialogImpl<ProgressDialog>
{
    public:
        ProgressDialog();

        ~ProgressDialog();

        enum { IDD = IDD_PROGRESSDIALOG };

        bool abort_processing;

        BEGIN_MSG_MAP(ProgressDialog)
            MESSAGE_HANDLER(WM_INITDIALOG, OnInitDialog)
            COMMAND_HANDLER(IDCANCEL, BN_CLICKED, OnClickedCancel)
            CHAIN_MSG_MAP(CAxDialogImpl<ProgressDialog>)
        END_MSG_MAP()

        // Handler prototypes:
        //  LRESULT MessageHandler(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);
        //  LRESULT CommandHandler(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled);
        //  LRESULT NotifyHandler(int idCtrl, LPNMHDR pnmh, BOOL& bHandled);

        LRESULT OnInitDialog(UINT uMsg, WPARAM wParam, LPARAM lParam, BOOL& bHandled);

        LRESULT OnClickedCancel(WORD wNotifyCode, WORD wID, HWND hWndCtl, BOOL& bHandled);
};

